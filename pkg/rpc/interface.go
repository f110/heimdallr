package rpc

func (x *RequestGetSignedList) SetCommonName(v string) {
	x.CommonName = v
}

func (x *RequestGetSignedList) SetDevice(v bool) {
	x.Device = v
}

func (x *RequestNewClientCert) SetCommonName(v string) {
	x.CommonName = v
}

func (x *RequestNewClientCert) SetOverrideCommonName(v string) {
	x.OverrideCommonName = v
}

func (x *RequestNewClientCert) SetDevice(v bool) {
	x.Device = v
}

func (x *RequestNewClientCert) SetComment(c string) {
	x.Comment = c
}
