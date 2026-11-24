package mail

import "errors"

// TEMPORARY lead-owned stub; deleted when templates.go is merged.
func Render(kind Kind, d TemplateData) (Message, error) {
	switch kind {
	case KindVerifyEmail, KindResetPassword:
		return Message{Subject: string(kind), Text: d.Link}, nil
	}
	return Message{}, errors.New("mail: unknown kind")
}
