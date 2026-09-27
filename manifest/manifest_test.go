package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/joshuajorel/scrambler/mask"
)

func fixture(t *testing.T) (Document, map[mask.KeyRef][]byte) {
	t.Helper()
	b, err := os.ReadFile("testdata/banking.json")
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	keys := make(map[mask.KeyRef][]byte)
	for _, p := range d.Policies {
		keys[p.Key.maskRef()] = []byte("0123456789abcdef")
	}
	return d, keys
}

func loadFixture(t *testing.T) (*Set, Document, map[mask.KeyRef][]byte) {
	t.Helper()
	d, keys := fixture(t)
	b, _ := json.Marshal(d)
	s, err := Load(bytes.NewReader(b), keys)
	if err != nil {
		t.Fatal(err)
	}
	return s, d, keys
}

func TestBankingRelationshipsAndRows(t *testing.T) {
	s, d, _ := loadFixture(t)
	data := map[string]any{
		"customer_number": "C000001", "national_id": "100000001",
		"email": "ava.nguyen.000001@example.test", "phone": "+1-202-555-0001",
		"primary_account_number": "700000000002", "primary_card_number": "4000000000000028",
		"account_number": "700000000002", "card_number": "4000000000000028",
		"customer_national_id": "100000001", "payer_national_id": "100000001",
		"payer_email": "ava.nguyen.000001@example.test", "beneficiary_account_number": "700000000002",
	}
	rows := map[string]map[string]any{}
	for _, f := range d.Bindings {
		table := f.Database + "." + f.Schema + "." + f.Table
		if rows[table] == nil {
			rows[table] = make(map[string]any)
		}
		v, ok := data[f.Column]
		if !ok {
			v = "left clear"
		}
		rows[table][f.ID()] = v
	}
	// The customer's account and card names differ from the child columns.
	var detector Detector
	masked := map[string]any{}
	for _, row := range rows {
		out, nulls, err := s.MaskRow(row, mask.Context{}, &detector)
		if err != nil || len(nulls) != 0 {
			t.Fatalf("mask row: %v, nulls %v", err, nulls)
		}
		for k, v := range out {
			masked[k] = v
		}
	}
	for _, edge := range d.Edges {
		if masked[edge.From] != masked[edge.To] {
			t.Fatalf("edge %s -> %s differs: %v != %v", edge.From, edge.To, masked[edge.From], masked[edge.To])
		}
	}
	if masked["postgresql.public.customers.given_name"] != "left clear" {
		t.Fatal("clear column changed")
	}
	if _, _, err := s.MaskRow(rows["postgresql.public.customers"], mask.Context{}, &detector); !errors.Is(err, ErrDuplicateOutput) || !strings.Contains(err.Error(), "postgresql.public.customers") {
		t.Fatalf("duplicate unique output: %v", err)
	}
	pg := rows["postgresql.public.customers"]
	pg["postgresql.public.customers.phone"] = nil
	_, nulls, err := s.MaskRow(pg, mask.Context{}, nil)
	if err != nil || len(nulls) != 1 || nulls[0].Binding != "postgresql.public.customers.phone" {
		t.Fatalf("NULL pass-through: %v %v", nulls, err)
	}
	pg["postgresql.public.customers.phone"] = "bad"
	if _, _, err := s.MaskRow(pg, mask.Context{}, nil); !errors.Is(err, ErrInvalidRow) || !strings.Contains(err.Error(), "postgresql.public.customers.phone") {
		t.Fatalf("specific row error: %v", err)
	}
	delete(pg, "postgresql.public.customers.phone")
	if _, _, err := s.MaskRow(pg, mask.Context{}, nil); !strings.Contains(err.Error(), "postgresql.public.customers.phone") {
		t.Fatalf("missing column: %v", err)
	}
}

func TestCodecConversionAndCapacity(t *testing.T) {
	d, keys := fixture(t)
	for i := range d.Bindings {
		switch d.Bindings[i].ID() {
		case "postgresql.public.customers.primary_account_number":
			d.Bindings[i].Codec = Codec{Kind: "zero_padded_numeric", Width: 12}
		case "oracle.BANK.ACCOUNTS.account_number":
			d.Bindings[i].Codec = Codec{Kind: "blank_padded_text", Width: 15}
		}
	}
	s, err := Compile(d, keys)
	if err != nil {
		t.Fatal(err)
	}
	pg := map[string]any{}
	for _, f := range d.Bindings {
		if f.Database == "postgresql" {
			pg[f.ID()] = "clear"
			if f.Mode == "mask" {
				pg[f.ID()] = map[string]string{"customer_number": "C000001", "national_id": "100000001", "email": "ava.nguyen.000001@example.test", "phone": "+1-202-555-0001", "primary_card_number": "4000000000000028"}[f.Column]
			}
		}
	}
	pg["postgresql.public.customers.primary_account_number"] = int64(700000000002)
	out, _, err := s.MaskRow(pg, mask.Context{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out["postgresql.public.customers.primary_account_number"] != int64(96897026892) {
		t.Fatalf("numeric output: %v", out["postgresql.public.customers.primary_account_number"])
	}
	oracle := map[string]any{}
	for _, f := range d.Bindings {
		if f.Database == "oracle" {
			oracle[f.ID()] = "clear"
			if f.Mode == "mask" {
				oracle[f.ID()] = map[string]string{"account_number": "700000000002   ", "customer_number": "C000001", "customer_national_id": "100000001", "card_number": "4000000000000028"}[f.Column]
			}
		}
	}
	out, _, err = s.MaskRow(oracle, mask.Context{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out["oracle.BANK.ACCOUNTS.account_number"] != "096897026892   " {
		t.Fatalf("padded output: %q", out["oracle.BANK.ACCOUNTS.account_number"])
	}
	d.Bindings[0].Codec.Width = 1
	if _, err := Compile(d, keys); !errors.Is(err, ErrInvalidManifest) || !strings.Contains(err.Error(), d.Bindings[0].ID()) {
		t.Fatalf("capacity check: %v", err)
	}
	d, keys = fixture(t)
	for i := range d.Bindings {
		if d.Bindings[i].ID() == "postgresql.public.customers.email" {
			d.Bindings[i].Codec = Codec{Kind: "zero_padded_numeric", Width: 30}
			if _, err := Compile(d, keys); !strings.Contains(err.Error(), d.Bindings[i].ID()) {
				t.Fatalf("numeric type check: %v", err)
			}
			break
		}
	}
	d, keys = fixture(t)
	for i := range d.Policies {
		if d.Policies[i].Domain == "account-number" {
			d.Policies[i].Alphabet += " "
			break
		}
	}
	for i := range d.Bindings {
		if d.Bindings[i].ID() == "postgresql.public.customers.primary_account_number" {
			d.Bindings[i].Codec = Codec{Kind: "blank_padded_text", Width: 12}
			if _, err := Compile(d, keys); !strings.Contains(err.Error(), "output may end in a space") || !strings.Contains(err.Error(), d.Bindings[i].ID()) {
				t.Fatalf("ambiguous blank padding: %v", err)
			}
			break
		}
	}
}

func TestManifestValidation(t *testing.T) {
	d, keys := fixture(t)
	for _, tc := range []struct {
		name   string
		change func(*Document)
		want   string
	}{
		{"undefined policy", func(d *Document) { d.Bindings[0].Policy = "missing" }, d.Bindings[0].ID()},
		{"divergent domain", func(d *Document) { d.Policies = append(d.Policies, d.Policies[0]) }, "customer-number"},
		{"edge mismatch", func(d *Document) { d.Edges[0].To = "oracle.BANK.ACCOUNTS.account_number" }, "edge"},
		{"unknown endpoint", func(d *Document) { d.Edges[0].To = "oracle.BANK.ACCOUNTS.missing" }, "missing"},
		{"bad golden", func(d *Document) { d.Goldens[0].Output = "wrong" }, "golden"},
		{"missing golden", func(d *Document) { d.Goldens = d.Goldens[:len(d.Goldens)-1] }, "phone-us"},
		{"bad scope", func(d *Document) { d.Policies[0].Scope = "column" }, "customer-number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := d
			copy.Policies = append([]Policy(nil), d.Policies...)
			copy.Bindings = append([]Field(nil), d.Bindings...)
			copy.Edges = append([]Edge(nil), d.Edges...)
			copy.Goldens = append([]Golden(nil), d.Goldens...)
			tc.change(&copy)
			_, err := Compile(copy, keys)
			if !errors.Is(err, ErrInvalidManifest) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
	badKey := make(map[mask.KeyRef][]byte)
	for k := range keys {
		badKey[k] = []byte("fedcba9876543210")
	}
	if _, err := Compile(d, badKey); !strings.Contains(err.Error(), "golden") {
		t.Fatalf("wrong key should fail golden: %v", err)
	}
	b, _ := json.Marshal(d)
	b = append(b, []byte(` {}`)...)
	if _, err := Load(bytes.NewReader(b), keys); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("trailing JSON: %v", err)
	}
	b, _ = json.Marshal(d)
	b = bytes.Replace(b, []byte(`"version":1`), []byte(`"version":1,"unknown":true`), 1)
	if _, err := Load(bytes.NewReader(b), keys); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestGoldenSeparateProcess(t *testing.T) {
	if os.Getenv("SCRAMBLER_MANIFEST_CHILD") == "1" {
		loadFixture(t)
		return
	}
	// Loading in a fresh process checks all pinned outputs and fingerprints.
	cmd := exec.Command(os.Args[0], "-test.run=^TestGoldenSeparateProcess$")
	cmd.Env = append(os.Environ(), "SCRAMBLER_MANIFEST_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("independent process: %v: %s", err, out)
	}
}

func TestMaskRowMixedScopes(t *testing.T) {
	d, keys := fixture(t)
	ctx := mask.Context{TenantID: "bank-a", RecordID: "payment-42"}
	inputs := map[string]string{
		"customer_number": "C000001", "account_number": "700000000002", "card_number": "4000000000000028",
		"payer_national_id": "100000001", "payer_email": "ava.nguyen.000001@example.test",
		"beneficiary_account_number": "700000000002",
	}
	want := map[string]string{}
	for _, g := range d.Goldens {
		if g.Binding == "postgresql.public.customers.customer_number" && g.Input == inputs["customer_number"] {
			want["sqlserver.dbo.payments.customer_number"] = g.Output
		}
	}
	for _, extra := range []struct {
		column, input string
		scope         mask.Scope
		golden        GoldenContext
	}{
		{"payment_reference", "0000012345", mask.Record, GoldenContext{TenantID: ctx.TenantID, RecordID: ctx.RecordID}},
		{"branch_code", "00012345", mask.TenantDomain, GoldenContext{TenantID: ctx.TenantID}},
	} {
		scope := map[mask.Scope]string{mask.Record: "record", mask.TenantDomain: "tenant_domain"}[extra.scope]
		p := Policy{Domain: extra.column, Version: "v1", Key: KeyReference{ID: "demo-" + extra.column, Version: "v1"}, Scope: scope, Alphabet: "0123456789", Width: len(extra.input)}
		keys[p.Key.maskRef()] = []byte("0123456789abcdef")
		compiled, err := mask.Compile(mask.Spec{DomainID: p.Domain, Version: p.Version, Scope: extra.scope, Alphabet: p.Alphabet, Width: p.Width}, p.Key.maskRef(), keys[p.Key.maskRef()])
		if err != nil {
			t.Fatal(err)
		}
		out, err := compiled.Mask(extra.input, mask.Context{TenantID: extra.golden.TenantID, RecordID: extra.golden.RecordID})
		if err != nil {
			t.Fatal(err)
		}
		d.Policies = append(d.Policies, p)
		id := "sqlserver.dbo.payments." + extra.column
		d.Goldens = append(d.Goldens, Golden{Binding: id, Input: extra.input, Output: out, Fingerprint: compiled.Fingerprint(), Context: &extra.golden})
		f := Field{Database: "sqlserver", Schema: "dbo", Table: "payments", Column: extra.column, Mode: "mask", Policy: p.Domain, Codec: Codec{Kind: "text", Width: p.Width}}
		replaced := false
		for i := range d.Bindings {
			if d.Bindings[i].ID() == id {
				d.Bindings[i], replaced = f, true
			}
		}
		if !replaced {
			d.Bindings = append(d.Bindings, f)
		}
		inputs[extra.column] = extra.input
		want[id] = out
	}
	s, err := Compile(d, keys)
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]any{}
	for _, f := range d.Bindings {
		if f.Database == "sqlserver" {
			row[f.ID()] = "clear"
			if f.Mode == "mask" {
				row[f.ID()] = inputs[f.Column]
			}
		}
	}
	out, _, err := s.MaskRow(row, ctx, nil)
	if err != nil {
		t.Fatalf("mixed-scope row: %v", err)
	}
	if len(want) != 3 {
		t.Fatalf("expected outputs: %v", want)
	}
	for id, v := range want {
		if out[id] != v {
			t.Fatalf("%s: got %v, want %v", id, out[id], v)
		}
	}
	for _, tc := range []struct {
		ctx  mask.Context
		want string
	}{
		{mask.Context{TenantID: ctx.TenantID}, "sqlserver.dbo.payments.payment_reference"},
		{mask.Context{RecordID: ctx.RecordID}, "sqlserver.dbo.payments.branch_code"},
	} {
		if _, _, err := s.MaskRow(row, tc.ctx, nil); !errors.Is(err, ErrInvalidRow) || !errors.Is(err, mask.ErrInvalidScope) || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("context %+v: %v", tc.ctx, err)
		}
	}
}
