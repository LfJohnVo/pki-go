package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func main() {
	//CSR Generation function
	CsrGeneration()
}

func CsrGeneration(){
	//This program needs use asn1 encoded
	fmt.Println("Begin CSR generation")
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	emailAddress := "john@gmail.com"
	subj := pkix.Name{
		CommonName:         "john.com",
		Country:            []string{"MX"},
		Province:           []string{"Mexico"},
		Locality:           []string{"CDMX"},
		Organization:       []string{"Silent4Business"},
		OrganizationalUnit: []string{"IT"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	//This lines exposes CSR encoded lines
	//pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	certOut, err := os.Create("csr.pem")

	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		log.Fatalf("Failed to write data to csr: %v", err)
	}

	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cst.pem: %v", err)
	}

	fmt.Println("End process..")
}
