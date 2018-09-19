//
// https://blog.cloudflare.com/eliminating-the-last-reasons-to-not-enable-ipv6/
// http://matsumpter.com/blog/2014/pseudo-ipv4-addresses-for-ipv6-users-openresty/
//

package main

import (
    "fmt"
    "flag"
    "os"               
    "log"
    "crypto/md5"
)

const (
    IPV6_ADDR_GLOBAL    = 0x0000
    IPV6_ADDR_LOOPBACK  = 0x0010
    IPV6_ADDR_LINKLOCAL = 0x0020
    IPV6_ADDR_SITELOCAL = 0x0040
    IPV6_ADDR_COMPATv4  = 0x0080
)

func pseudo_ipv4(intf *string) *string {

    var prefix int
    var scope  int
    var ignore1 int
    var ignore2 int
    var ipv6 = make([]byte, 16)
    var intname = make([]byte, 16)

    ipv4 := "127.0.0.1"

    file, err := os.Open("/proc/net/if_inet6") // For read access.

    if err != nil {
	log.Fatal(err)
        return &ipv4
    }

    defer file.Close()

    for {
        count, err := fmt.Fscanf(file,
                            "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x %x %x %x %x\t%s",
                            &ipv6[0],
                            &ipv6[1],
                            &ipv6[2],
                            &ipv6[3],
                            &ipv6[4],
                            &ipv6[5],
                            &ipv6[6],
                            &ipv6[7],
                            &ipv6[8],
                            &ipv6[9],
                            &ipv6[10],
                            &ipv6[11],
                            &ipv6[12],
                            &ipv6[13],
                            &ipv6[14],
                            &ipv6[15],
                            &ignore1,
                            &prefix,
                            &scope,
                            &ignore2,
                            &intname )

        interface_name := string(intname)

        if interface_name == *intf && scope == IPV6_ADDR_GLOBAL {
      
            hasher := md5.New()
 
            hasher.Write(ipv6)
           
            hash_bytes := hasher.Sum(nil)

            address_bytes := hash_bytes[12:16]

            // tiddle into class E
            address_bytes[0] = ( address_bytes[0] & 0x0F )
            address_bytes[0] = ( address_bytes[0] | 0xF0 )

            ipv4 = fmt.Sprintf("%d.%d.%d.%d", address_bytes[0],
                                               address_bytes[1],
                                               address_bytes[2],
                                               address_bytes[3])

            break
        }
 
        if err != nil || count != 21 {
            break
        }
    }

    return &ipv4
}

func main() {

    InterfacePtr := flag.String("interface", "eth0", "Interface to extract IPv6 from")

    flag.Parse()

    ipv4 := pseudo_ipv4(InterfacePtr)

    fmt.Println(*ipv4)

    return
}
