# go-zamane
WIP

*Getting a signed timestamp:*
```go
algo := cryptoid.SHA512
digester := algo.Hash.New()

file, _ := os.Open("file-to-be-timestamped.txt")
io.Copy(digester, file)

client, _ := zamane.NewClient("999999", "12345678")

tsq, tsr, _ := client.RequestTimestamp(nil, digester.Sum(nil), algo)

tsqDER, _ := asn1.Marshal(*tsq)
tsrDER, _ := asn1.Marshal(*tsr)

ioutil.WriteFile("file-to-be-timestamped.tsq", tsqDER, 0644)
ioutil.WriteFile("file-to-be-timestamped.tsr", tsrDER, 0644)
```

*Getting the amount of credit remaining:*
```go
client, _ := zamane.NewClient("999999", "12345678")
credit, _ := client.RemainingCredit(nil)

fmt.Printf("Remaining credit: %d\n", credit)
```
