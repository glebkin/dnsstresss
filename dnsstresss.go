package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/miekg/dns"
)

// query is a DNS request query containing domain name and record type
type query struct {
	// domain requested by DNS server
	domain string
	// recordType is a type of requested DNS record
	recordType uint16
}

// Mapping of string record types to its uint16 dns library representation
var recordTypes = map[string]uint16{
	"A":    dns.TypeA,
	"AAAA": dns.TypeAAAA,
	"ANY":  dns.TypeANY,
	"MX":   dns.TypeMX,
	"NS":   dns.TypeNS,
	"TXT":  dns.TypeTXT,
}

// Runtime options
var (
	concurrency     int
	displayInterval int
	verbose         bool
	iterative       bool
	resolver        string
	randomIds       bool
	flood           bool

	// Path to file with the list of DNS requests in the following format: <domain> <query-type>
	// Example:
	//		6138.7370686f746f73.616b.666263646e.6e6574.80h3f617b3a.webcfs00.com.	MX
	// 		frycomm.com.s9b2.psmtp.com.	A
	// 		www.apple.com.	A
	// 		170.44.153.187.in-addr.arpa.	PTR
	dataFile string
)

func init() {
	flag.IntVar(&concurrency, "concurrency", 50,
		"Internal buffer")
	flag.IntVar(&displayInterval, "d", 1000,
		"Update interval of the stats (in ms)")
	flag.BoolVar(&verbose, "v", false,
		"Verbose logging")
	flag.BoolVar(&randomIds, "random", false,
		"Use random Request Identifiers for each query")
	flag.BoolVar(&iterative, "i", false,
		"Do an iterative query instead of recursive (to stress authoritative nameservers)")
	flag.StringVar(&resolver, "r", "127.0.0.1:53",
		"Resolver to test against")
	flag.BoolVar(&flood, "f", false,
		"Don't wait for an answer before sending another")
	flag.StringVar(&dataFile, "dataFile", "",
		"Path to data file containing DNS requests in format '<domain name> <query type>'")
}

func main() {
	fmt.Printf("dnsstresss - dns stress tool\n\n")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, strings.Join([]string{
			"Send DNS requests as fast as possible to a given server and display the rate.",
			"",
			"Usage: dnsstresss [option ...] targetdomain [targetdomain [...] ]",
			"",
		}, "\n"))
		flag.PrintDefaults()
	}

	flag.Parse()

	parsedResolver, err := ParseIPPort(resolver)
	if err != nil {
		fmt.Println(aurora.Sprintf(aurora.Red("%s (%s)"), "Unable to parse the resolver address", err))
		os.Exit(2)
	}
	resolver = parsedResolver

	var queries []query
	if dataFile != "" {
		var f *os.File
		f, err = os.Open(dataFile)
		if err != nil {
			fmt.Println(aurora.Sprintf(aurora.Red("%s (%s)"), "Unable to open dataFile", err))
			os.Exit(2)
		}
		defer f.Close()

		r := bufio.NewReader(f)
		for {
			var str string
			str, err = r.ReadString('\n')
			if err == io.EOF {
				break
			} else if err != nil {
				fmt.Println(aurora.Sprintf(aurora.Red("%s (%s)"), "Unable to read dataFile", err))
				os.Exit(2)
			}

			spl := strings.Fields(str)
			queries = append(queries, query{
				domain:     spl[0],
				recordType: recordTypes[spl[1]],
			})
		}
	}

	// all remaining parameters are treated as domains to be used in round-robin in the threads
	if len(queries) == 0 {
		for index, element := range flag.Args() {
			queries[index] = query{
				domain:     element,
				recordType: dns.TypeA,
			}
		}
	}

	// We need at least one target domain
	if len(queries) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Create a channel for communicating the number of sent messages
	sentCounterCh := make(chan statsMessage, concurrency)

	// Run concurrently
	step := len(queries) / concurrency
	for threadID := 0; threadID < concurrency; threadID++ {
		go linearResolver(threadID, queries[:step], sentCounterCh)
		queries = queries[step:]
	}
	fmt.Print(aurora.Faint(fmt.Sprintf("Started %d threads.\n", runtime.NumCPU())))

	if !flood {
		go timerStats(sentCounterCh)
	} else {
		fmt.Println("Flooding mode, nothing will be printed.")
	}
	// We still need this useless routine to empty the channels, even when flooding
	displayStats(sentCounterCh)
}

func linearResolver(threadID int, queries []query, sentCounterCh chan<- statsMessage) {
	// Resolve the domain as fast as possible
	if verbose {
		fmt.Printf("Starting thread #%d.\n", threadID)
	}

	// Every N steps, we will tell the stats module how many requests we sent
	displayStep := 5
	maxRequestID := big.NewInt(65536)
	errors := 0

	var start time.Time
	var elapsed time.Duration    // Total time spent resolving
	var maxElapsed time.Duration // Maximum time took by a request

	for {
		for _, q := range queries {
			message := new(dns.Msg).SetQuestion(q.domain, q.recordType)
			if iterative {
				message.RecursionDesired = false
			}

			for i := 0; i < displayStep; i++ {
				// Try to resolve the domain
				if randomIds {
					// Regenerate message Id to avoid servers dropping (seemingly) duplicate messages
					newid, _ := rand.Int(rand.Reader, maxRequestID)
					message.Id = uint16(newid.Int64())
				}

				if flood {
					go dnsExchange(resolver, message)
				} else {
					start = time.Now()
					err := dnsExchange(resolver, message)
					spent := time.Since(start)
					elapsed += spent
					if spent > maxElapsed {
						maxElapsed = spent
					}
					if err != nil {
						if verbose {
							fmt.Printf("%s error: %d (%s)\n", q.domain, err, resolver)
						}
						errors++
					}
				}
			}

			// Update the counter of sent requests and requests
			sentCounterCh <- statsMessage{
				sent:       displayStep,
				err:        errors,
				elapsed:    elapsed,
				maxElapsed: maxElapsed,
			}
			errors = 0
			elapsed = 0
			maxElapsed = 0
		}
	}
}

func dnsExchange(resolver string, message *dns.Msg) error {
	//XXX: How can we share the connection between subsequent attempts ?
	dnsconn, err := net.Dial("udp", resolver)
	if err != nil {
		return err
	}
	co := &dns.Conn{Conn: dnsconn}
	defer co.Close()

	// Actually send the message and wait for answer
	co.WriteMsg(message)

	_, err = co.ReadMsg()
	return err
}
