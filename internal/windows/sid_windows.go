package windows

func restrictedCodeSID() SID {
	return SID{text: "S-1-5-12", kind: sidKindRestrictedCode}
}

func (sid SID) isRestrictedCode() bool {
	return sid.kind == sidKindRestrictedCode && sid.text == "S-1-5-12" && len(sid.binary()) == 12
}
