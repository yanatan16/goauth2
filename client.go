package goauth2

type ClientImpl struct {
	id    string
	ctype string
}

func NewClient(id string, clientType string) Client {
	return &ClientImpl{
		id:    id,
		ctype: clientType,
	}
}

func (c *ClientImpl) ID() string {
	return c.id
}

func (c *ClientImpl) Type() string {
	return c.ctype
}

func (c *ClientImpl) ValidateRedirectURI(uri string) string {
	//TODO
	return uri
}
