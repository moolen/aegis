package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var errTLSSNIMissing = errors.New("tls client hello did not include sni")

func readClientHello(r *bufio.Reader) ([]byte, string, error) {
	recordHeader, err := readTLSBytes(r, 5)
	if err != nil {
		return nil, "", fmt.Errorf("read tls record header: %w", err)
	}
	if recordHeader[0] != 22 {
		return nil, "", fmt.Errorf("unexpected tls content type %d", recordHeader[0])
	}

	recordLength := int(binary.BigEndian.Uint16(recordHeader[3:5]))
	if recordLength <= 0 {
		return nil, "", fmt.Errorf("invalid tls record length %d", recordLength)
	}

	recordBody, err := readTLSBytes(r, recordLength)
	if err != nil {
		return nil, "", fmt.Errorf("read tls record body: %w", err)
	}

	clientHello := append(recordHeader, recordBody...)
	sni, err := parseClientHelloSNI(recordBody)
	if err != nil {
		return nil, "", err
	}

	return clientHello, sni, nil
}

func parseClientHelloSNI(recordBody []byte) (string, error) {
	if len(recordBody) < 4 {
		return "", fmt.Errorf("short tls handshake")
	}
	if recordBody[0] != 1 {
		return "", fmt.Errorf("unexpected tls handshake type %d", recordBody[0])
	}

	handshakeLength := int(recordBody[1])<<16 | int(recordBody[2])<<8 | int(recordBody[3])
	if len(recordBody[4:]) < handshakeLength {
		return "", fmt.Errorf("incomplete tls client hello")
	}

	hello := recordBody[4 : 4+handshakeLength]
	if len(hello) < 34 {
		return "", fmt.Errorf("short tls client hello")
	}

	offset := 34
	if offset >= len(hello) {
		return "", fmt.Errorf("missing tls session id")
	}
	sessionIDLength := int(hello[offset])
	offset++
	if offset+sessionIDLength > len(hello) {
		return "", fmt.Errorf("invalid tls session id length")
	}
	offset += sessionIDLength

	if offset+2 > len(hello) {
		return "", fmt.Errorf("missing tls cipher suites length")
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2
	if offset+cipherSuitesLength > len(hello) {
		return "", fmt.Errorf("invalid tls cipher suites length")
	}
	offset += cipherSuitesLength

	if offset >= len(hello) {
		return "", fmt.Errorf("missing tls compression methods")
	}
	compressionMethodsLength := int(hello[offset])
	offset++
	if offset+compressionMethodsLength > len(hello) {
		return "", fmt.Errorf("invalid tls compression methods length")
	}
	offset += compressionMethodsLength

	if offset == len(hello) {
		return "", errTLSSNIMissing
	}
	if offset+2 > len(hello) {
		return "", fmt.Errorf("missing tls extensions length")
	}
	extensionsLength := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2
	if offset+extensionsLength > len(hello) {
		return "", fmt.Errorf("invalid tls extensions length")
	}

	extensions := hello[offset : offset+extensionsLength]
	for len(extensions) >= 4 {
		extensionType := binary.BigEndian.Uint16(extensions[:2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extensionLength > len(extensions) {
			return "", fmt.Errorf("invalid tls extension length")
		}
		extensionData := extensions[:extensionLength]
		extensions = extensions[extensionLength:]

		if extensionType != 0 {
			continue
		}

		if len(extensionData) < 2 {
			return "", fmt.Errorf("invalid tls server name extension")
		}
		serverNameListLength := int(binary.BigEndian.Uint16(extensionData[:2]))
		serverNameList := extensionData[2:]
		if serverNameListLength > len(serverNameList) {
			return "", fmt.Errorf("invalid tls server name list length")
		}
		serverNameList = serverNameList[:serverNameListLength]

		for len(serverNameList) >= 3 {
			nameType := serverNameList[0]
			nameLength := int(binary.BigEndian.Uint16(serverNameList[1:3]))
			serverNameList = serverNameList[3:]
			if nameLength > len(serverNameList) {
				return "", fmt.Errorf("invalid tls server name length")
			}
			if nameType == 0 {
				if nameLength == 0 {
					return "", errTLSSNIMissing
				}
				return string(serverNameList[:nameLength]), nil
			}
			serverNameList = serverNameList[nameLength:]
		}

		return "", errTLSSNIMissing
	}

	return "", errTLSSNIMissing
}

func readTLSBytes(r *bufio.Reader, length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
