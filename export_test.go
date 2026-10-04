package rndc

func parseTimeoutForTest(s string) error {
	_, err := parseTimeout(s)
	return err
}

func marshalDictForTest(d *dict, ignoreAuth bool) ([]byte, error) {
	return marshalDict(d, ignoreAuth)
}

func unmarshalDictForTest(data []byte) (*dict, error) {
	return unmarshalDict(data)
}

func createHMACForTest(secret, data []byte, algo Algorithm) ([]byte, error) {
	return createHMAC(secret, data, algo)
}

func verifyHMACForTest(secret, data []byte, algo Algorithm, remote []byte) bool {
	return verifyHMAC(secret, data, algo, remote)
}

func packAuthForTest(algo Algorithm, digest []byte) (string, []byte) {
	return packAuth(algo, digest)
}

func parsePortForTest(s string) (int, error) {
	return parsePort(s)
}

func (d *dict) SetRaw(key string, raw []byte)   { d.setRaw(key, raw) }
func (d *dict) SetString(key, s string)         { d.setString(key, s) }
func (d *dict) SetDict(key string, child *dict) { d.setDict(key, child) }
func (d *dict) GetRaw(key string) []byte        { return d.getRaw(key) }
func (d *dict) GetDict(key string) *dict        { return d.getDict(key) }
