package main

import (
	"encoding/binary"
	"github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
	"net"
)

var log = logrus.New()

// Decode a payload of []byte into a TemplateField object
func decodeSingleTemplateField(payload []byte) (TemplateField, int) {
	tf := TemplateField{
		ElementId: binary.BigEndian.Uint16(payload[0:2]),
		Length:    binary.BigEndian.Uint16(payload[2:4]),
	}

	if tf.ElementId > 0x8000 {
		tf.ElementId = tf.ElementId & 0x7fff
		tf.EnterpriseNumber = binary.BigEndian.Uint32(payload[0:4])
		return tf, 8
	}

	return tf, 4
}

// Decode a payload of []byte into a single option, stored in options by name
// Identifiers/types from https://www.iana.org/assignments/ipfix/ipfix.xml
func decodeSingleOption(byteSlice []byte, field TemplateField, options Options) {
	// Check we have enough data
	if len(byteSlice) < int(field.Length) {
		return
	}

	// Handle each enterprise
	switch field.EnterpriseNumber {
	case 0:
		// Handle elements for enterprise 0
		switch field.ElementId {
		case 34:
			// samplingInterval
			options["samplingInterval"] = binary.BigEndian.Uint32(byteSlice[:int(field.Length)])
		case 36:
			// flowActiveTimeout
			options["flowActiveTimeout"] = binary.BigEndian.Uint16(byteSlice[:int(field.Length)])
		case 37:
			// flowIdleTimeout
			options["flowIdleTimeout"] = binary.BigEndian.Uint16(byteSlice[:int(field.Length)])
		case 41:
			// exportedMessageTotalCount
			options["exportedMessageTotalCount"] = binary.BigEndian.Uint64(byteSlice[:int(field.Length)])
		case 42:
			// exportedFlowRecordTotalCount
			options["exportedFlowRecordTotalCount"] = binary.BigEndian.Uint64(byteSlice[:int(field.Length)])
		case 130:
			// exporterIPv4Address
			options["exporterIPv4Address"] = net.IP(byteSlice[:int(field.Length)])
		case 131:
			// exporterIPv6Address
			options["exporterIPv6Address"] = net.IP(byteSlice[:int(field.Length)])
		case 144:
			// exportingProcessId
			options["exportingProcessId"] = binary.BigEndian.Uint32(byteSlice[:int(field.Length)])
		case 160:
			// systemInitTimeMilliseconds
			options["exportingProcessId"] = int64(binary.BigEndian.Uint64(byteSlice[:int(field.Length)]))
		case 214:
			// exportProtocolVersion
			options["exportProtocolVersion"] = uint8(byteSlice[0])
		case 215:
			// exportTransportProtocol
			options["exportTransportProtocol"] = uint8(byteSlice[0])
		}
	}
}

// Decode a payload of []byte into an OptionsTemplate object, stored in templateCache by ID
func parseOptionsTemplate(header IpfixHeader, payload []byte, templateCache *lru.Cache) (Options, bool) {
	// Check we have enough bytes for an options template
	if len(payload) <= 26 {
		return nil, false
	}

	// Decode the options info
	template := OptionsTemplate{
		TemplateId:      binary.BigEndian.Uint16(payload[0:2]),
		FieldCount:      binary.BigEndian.Uint16(payload[2:4]),
		ScopeFieldCount: binary.BigEndian.Uint16(payload[4:6]),
	}
	log.Debugf("Decoded IPFIX options template header:\n"+
		"  Template ID: %d\n"+
		"  Field Count: %d\n"+
		"  Scope Field Count: %d\n",
		template.TemplateId,
		template.FieldCount,
		template.ScopeFieldCount)

	// We will nibble off this
	byteSlice := []byte(payload[6:])

	// Get all scope entries
	for i := template.ScopeFieldCount; i > 0; i-- {
		tf, cut := decodeSingleTemplateField(byteSlice)
		template.ScopeField = append(template.ScopeField, tf)

		if len(byteSlice) < cut {
			break
		}
		byteSlice = byteSlice[cut:]
	}

	// Get all field entries
	for i := template.FieldCount - template.ScopeFieldCount; i > 0; i-- {
		tf, cut := decodeSingleTemplateField(byteSlice)
		template.Field = append(template.Field, tf)

		if len(byteSlice) < cut {
			break
		}
		byteSlice = byteSlice[cut:]
	}

	// Store the template in the cache for later
	templateCache.Add(template.TemplateId, template)
	return nil, true
}

// Decode a payload of []byte into an Options object
// Requires templateCache to contain the template ID in the decoded header
func parseOptions(header IpfixHeader, payload []byte, templateCache *lru.Cache) (Options, bool) {
	// Check we have a template for this payload
	cacheEntry, ok := templateCache.Get(header.SetId)
	if !ok {
		return nil, true
	}
	template := cacheEntry.(OptionsTemplate)

	// Create our final data structure
	options := Options{}

	// We will nibble off this
	byteSlice := []byte(payload)

	// Read all scope field separators
	for i := 0; i < len(template.ScopeField); i++ {
		decodeSingleOption(byteSlice, template.ScopeField[i], options)

		if len(byteSlice) < int(template.ScopeField[i].Length) {
			break
		}
		byteSlice = byteSlice[int(template.ScopeField[i].Length):]
	}

	// Read all field separators
	for i := 0; i < len(template.Field); i++ {
		decodeSingleOption(byteSlice, template.Field[i], options)

		if len(byteSlice) < int(template.Field[i].Length) {
			break
		}
		byteSlice = byteSlice[int(template.Field[i].Length):]
	}

	return options, true
}

func parsePayload(payload []byte, templateCache *lru.Cache) (Options, bool) {
	// Check we have enough bytes for the IPFIX header
	if len(payload) < 18 {
		return nil, false
	}

	// Decoder IPFIX header
	header := IpfixHeader{
		Version:        binary.BigEndian.Uint16(payload[0:2]),
		MessageLength:  binary.BigEndian.Uint16(payload[2:4]),
		ExportTime:     binary.BigEndian.Uint32(payload[4:8]),
		SequenceNumber: binary.BigEndian.Uint32(payload[8:12]),
		DomainId:       binary.BigEndian.Uint32(payload[12:16]),
		SetId:          binary.BigEndian.Uint16(payload[16:20]),
	}
	log.Debugf("Decoded payload header:\n"+
		"  Version: %d\n"+
		"  Length: %d\n"+
		"  Export Time: %d\n"+
		"  Sequence Number: %d\n"+
		"  Domain ID: %d\n"+
		"  Set ID: %d\n",
		header.Version, header.MessageLength, header.ExportTime,
		header.SequenceNumber, header.DomainId, header.SetId)

	// Check we have a protocol version of 10 (IPFIX)
	if header.Version != 10 {
		return nil, false
	}

	// Check we have enough data
	if len(payload) <= 20 {
		return nil, false
	}

	if header.SetId == 3 {
		// Options template
		return parseOptionsTemplate(header, payload[20:], templateCache)
	} else if header.SetId >= 256 {
		// Options payload
		return parseOptions(header, payload[20:], templateCache)
	}

	// Not something we can parse
	return nil, false
}
