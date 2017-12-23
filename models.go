package main

type IpfixHeader struct {
	Version        uint16
	MessageLength  uint16
	ExportTime     uint32
	SequenceNumber uint32
	DomainId       uint32
	SetId          uint16
}

type TemplateField struct {
	ElementId        uint16
	Length           uint16
	EnterpriseNumber uint32
}

type OptionsTemplate struct {
	TemplateId      uint16
	FieldCount      uint16
	Field           []TemplateField
	ScopeFieldCount uint16
	ScopeField      []TemplateField
}

type Options map[string]interface{}
