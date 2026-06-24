package smb2

import "unicode/utf16"

// MS-DFSC wire structures for DFS referral resolution
// (FSCTL_DFS_GET_REFERRALS). The request is encoded as the IOCTL input
// buffer; the response is decoded from the IOCTL output buffer.

// dfsNameListReferral is the ReferralEntryFlags bit that marks a V3/V4 entry
// as a name-list (domain/DC) referral, which uses a different layout without a
// single NetworkAddress. Regular DFS link targets do not set it.
const dfsNameListReferral = 0x0002

// ReqGetDfsReferral is the REQ_GET_DFS_REFERRAL input buffer (MS-DFSC 2.2.2).
// It implements Encoder so it can be used as IoctlRequest.Input.
type ReqGetDfsReferral struct {
	MaxReferralLevel uint16
	RequestFileName  string // DFS path, e.g. `\server\namespace\link`
}

func (r *ReqGetDfsReferral) Size() int {
	// MaxReferralLevel (2) + UTF-16LE filename + null terminator (2).
	return 2 + len(utf16.Encode([]rune(r.RequestFileName)))*2 + 2
}

func (r *ReqGetDfsReferral) Encode(b []byte) {
	le.PutUint16(b[0:2], r.MaxReferralLevel)
	off := 2
	for _, c := range utf16.Encode([]rune(r.RequestFileName)) {
		le.PutUint16(b[off:off+2], c)
		off += 2
	}
	le.PutUint16(b[off:off+2], 0) // null terminator
}

// DfsReferral is one decoded referral entry. NetworkAddress is the target the
// client should reconnect to (e.g. `\server\share` or `\server\share\path`).
type DfsReferral struct {
	VersionNumber  uint16
	ServerType     uint16
	Flags          uint16
	TimeToLive     uint32
	DFSPath        string
	NetworkAddress string
}

// RespGetDfsReferralDecoder decodes a RESP_GET_DFS_REFERRAL output buffer
// (MS-DFSC 2.2.4). It is defensive against malformed/truncated input.
type RespGetDfsReferralDecoder []byte

func (r RespGetDfsReferralDecoder) IsInvalid() bool {
	return len(r) < 8
}

// PathConsumed is the number of bytes of the request path the server resolved.
func (r RespGetDfsReferralDecoder) PathConsumed() uint16 {
	return le.Uint16(r[0:2])
}

func (r RespGetDfsReferralDecoder) NumberOfReferrals() uint16 {
	return le.Uint16(r[2:4])
}

func (r RespGetDfsReferralDecoder) ReferralHeaderFlags() uint32 {
	return le.Uint32(r[4:8])
}

// Referrals decodes every referral entry. Entry string offsets are relative to
// the start of their own entry. Unknown/name-list entries yield an empty
// NetworkAddress rather than failing the whole parse.
func (r RespGetDfsReferralDecoder) Referrals() []DfsReferral {
	if r.IsInvalid() {
		return nil
	}

	n := int(r.NumberOfReferrals())
	refs := make([]DfsReferral, 0, n)

	cur := 8
	for i := 0; i < n; i++ {
		if cur+8 > len(r) {
			break
		}
		size := int(le.Uint16(r[cur+2 : cur+4]))
		if size < 8 || cur+size > len(r) {
			break
		}
		// String offsets are relative to the entry start, but the strings live in
		// a shared area AFTER the fixed entries — i.e. past this entry's `size`.
		// Resolve offsets against the whole remaining buffer, not a size-bounded
		// slice; `size` is only used to advance to the next entry.
		entry := r[cur:]

		ref := DfsReferral{
			VersionNumber: le.Uint16(entry[0:2]),
			ServerType:    le.Uint16(entry[4:6]),
			Flags:         le.Uint16(entry[6:8]),
		}

		switch ref.VersionNumber {
		case 1:
			// DFS_REFERRAL_V1: ShareName is inline, right after the header.
			ref.NetworkAddress = dfsStringAt(entry, 8)
		case 2:
			// DFS_REFERRAL_V2: Proximity(4) TTL(4) DFSPathOffset(2)
			// DFSAlternatePathOffset(2) NetworkAddressOffset(2).
			if len(entry) >= 22 {
				ref.TimeToLive = le.Uint32(entry[12:16])
				ref.DFSPath = dfsStringAt(entry, le.Uint16(entry[16:18]))
				ref.NetworkAddress = dfsStringAt(entry, le.Uint16(entry[20:22]))
			}
		case 3, 4:
			// DFS_REFERRAL_V3/V4 (normal, non-name-list): TTL(4)
			// DFSPathOffset(2) DFSAlternatePathOffset(2) NetworkAddressOffset(2).
			if len(entry) >= 18 {
				ref.TimeToLive = le.Uint32(entry[8:12])
				if ref.Flags&dfsNameListReferral == 0 {
					ref.DFSPath = dfsStringAt(entry, le.Uint16(entry[12:14]))
					ref.NetworkAddress = dfsStringAt(entry, le.Uint16(entry[16:18]))
				}
				// Name-list (domain/DC) referrals use a different layout and are
				// not needed to follow a link target; left unparsed for now.
			}
		}

		refs = append(refs, ref)
		cur += size
	}

	return refs
}

// dfsStringAt reads a null-terminated UTF-16LE string at an entry-relative
// offset, with bounds checking.
func dfsStringAt(entry []byte, off uint16) string {
	if int(off) >= len(entry) {
		return ""
	}
	return dfsDecodeUTF16z(entry[off:])
}

func dfsDecodeUTF16z(b []byte) string {
	var u16 []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := le.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		u16 = append(u16, c)
	}
	return string(utf16.Decode(u16))
}
