package selector

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"honeyghost/cli/internal/model"
)

func numberAtom(field model.FilterField, compare model.FilterCompare, numbers ...uint32) *model.FilterExpr {
	return &model.FilterExpr{Atom: &model.FilterAtom{
		Field: field, Compare: compare, Numbers: numbers,
	}}
}

func typeAtom(compare model.FilterCompare, types ...model.EventType) *model.FilterExpr {
	return &model.FilterExpr{Atom: &model.FilterAtom{
		Field: model.FilterFieldType, Compare: compare, Types: types,
	}}
}

func kindAtom(compare model.FilterCompare, kinds ...model.EventKind) *model.FilterExpr {
	return &model.FilterExpr{Atom: &model.FilterAtom{
		Field: model.FilterFieldKind, Compare: compare, Kinds: kinds,
	}}
}

func roleAtom(compare model.FilterCompare, labels ...string) *model.FilterExpr {
	return &model.FilterExpr{Atom: &model.FilterAtom{
		Field: model.FilterFieldRoleLabel, Compare: compare, Strings: labels,
	}}
}

func logicExpr(logic model.FilterLogic, kids ...*model.FilterExpr) *model.FilterExpr {
	out := &model.FilterExpr{Logic: logic}
	for _, kid := range kids {
		out.Kids = append(out.Kids, *kid)
	}
	return out
}

func TestParseExpr(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   *model.FilterExpr
	}{
		{"none", nil, nil},
		{"empty list", []string{}, nil},
		{
			"single numeric",
			[]string{"pid=1234"},
			numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1234),
		},
		{
			"numbers deduped and sorted",
			[]string{"pid=9,2,9"},
			numberAtom(model.FilterFieldPID, model.FilterCompareEq, 2, 9),
		},
		{
			"types case insensitive and canonical",
			[]string{"type=FILE,SYSCALL,network,ipc,syscall"},
			typeAtom(model.FilterCompareEq,
				model.EventTypeSyscall, model.EventTypeFile,
				model.EventTypeNetwork, model.EventTypeIPC),
		},
		{
			"kinds case insensitive and canonical",
			[]string{"kind=EXEC,process,exec"},
			kindAtom(model.FilterCompareEq, model.EventKindProcess, model.EventKindExec),
		},
		{
			"role prefix",
			[]string{"role~=registry/,nginx"},
			roleAtom(model.FilterComparePrefix, "nginx", "registry/"),
		},
		{
			"not in",
			[]string{"pid!=1,2"},
			numberAtom(model.FilterFieldPID, model.FilterCompareNe, 1, 2),
		},
		{
			"role not in",
			[]string{"role!=nginx,redis"},
			roleAtom(model.FilterCompareNe, "nginx", "redis"),
		},
		{
			"quoted comma",
			[]string{"role=\"a,b\""},
			roleAtom(model.FilterCompareEq, "a,b"),
		},
		{
			"escaped comma",
			[]string{"role=a\\,b"},
			roleAtom(model.FilterCompareEq, "a,b"),
		},
		{
			"bare backslash is literal",
			[]string{"role=a\\b"},
			roleAtom(model.FilterCompareEq, "a\\b"),
		},
		{
			"trailing bare backslash is literal",
			[]string{"role=a\\"},
			roleAtom(model.FilterCompareEq, "a\\"),
		},
		{
			"single quoted whitespace",
			[]string{"role='a b'"},
			roleAtom(model.FilterCompareEq, "a b"),
		},
		{
			"quoted escaped quote",
			[]string{`role="a\"b"`},
			roleAtom(model.FilterCompareEq, `a"b`),
		},
		{
			"and/or precedence",
			[]string{"pid=1 or pid=2 and pid=3"},
			logicExpr(model.FilterLogicOr,
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1),
				logicExpr(model.FilterLogicAnd,
					numberAtom(model.FilterFieldPID, model.FilterCompareEq, 2),
					numberAtom(model.FilterFieldPID, model.FilterCompareEq, 3))),
		},
		{
			"parentheses",
			[]string{"(pid=1 or pid=2) and pid=3"},
			logicExpr(model.FilterLogicAnd,
				logicExpr(model.FilterLogicOr,
					numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1),
					numberAtom(model.FilterFieldPID, model.FilterCompareEq, 2)),
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 3)),
		},
		{
			"not binds tighter than and",
			[]string{"not pid=1 and pid=2"},
			logicExpr(model.FilterLogicAnd,
				logicExpr(model.FilterLogicNot,
					numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1)),
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 2)),
		},
		{
			"symbolic operators",
			[]string{"pid=1 && !(pid=2 || pid=3)"},
			logicExpr(model.FilterLogicAnd,
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1),
				logicExpr(model.FilterLogicNot,
					logicExpr(model.FilterLogicOr,
						numberAtom(model.FilterFieldPID, model.FilterCompareEq, 2),
						numberAtom(model.FilterFieldPID, model.FilterCompareEq, 3)))),
		},
		{
			"keywords case insensitive",
			[]string{"pid=1 AND NOT pid=2"},
			logicExpr(model.FilterLogicAnd,
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1),
				logicExpr(model.FilterLogicNot,
					numberAtom(model.FilterFieldPID, model.FilterCompareEq, 2))),
		},
		{
			"zero values allowed for literals",
			[]string{"ppid=0 and roleID=0 and contextID=0"},
			logicExpr(model.FilterLogicAnd,
				numberAtom(model.FilterFieldPPID, model.FilterCompareEq, 0),
				numberAtom(model.FilterFieldRoleID, model.FilterCompareEq, 0),
				numberAtom(model.FilterFieldContextID, model.FilterCompareEq, 0)),
		},
		{
			"repeated expressions intersect",
			[]string{"pid=1 or pid=2", "pid=1"},
			logicExpr(model.FilterLogicAnd,
				logicExpr(model.FilterLogicOr,
					numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1),
					numberAtom(model.FilterFieldPID, model.FilterCompareEq, 2)),
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1)),
		},
		{
			"repeated expressions flatten top-level and",
			[]string{"pid=1 and pid=2", "pid=3"},
			logicExpr(model.FilterLogicAnd,
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1),
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 2),
				numberAtom(model.FilterFieldPID, model.FilterCompareEq, 3)),
		},
		{
			"whitespace around operators",
			[]string{"pid = 1, 2"},
			numberAtom(model.FilterFieldPID, model.FilterCompareEq, 1, 2),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseExpr(tt.values)
			if err != nil {
				t.Fatalf("ParseExpr: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseExpr = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseExprErrors(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"empty", []string{""}, "empty expression"},
		{"whitespace only", []string{"   "}, "empty expression"},
		{"empty repeated", []string{"pid=1", " "}, "empty expression"},
		{"dangling and", []string{"pid=1 and"}, "expected a predicate"},
		{"pid zero", []string{"pid=0"}, "must be greater than 0"},
		{"empty numeric", []string{"pid="}, "expected a value"},
		{"empty role", []string{"role="}, "expected a value"},
		{"empty quoted", []string{"role=\"\""}, "empty value"},
		{"empty prefix", []string{"role~=\"\""}, "empty value"},
		{"trailing comma", []string{"role=a,"}, "expected a value"},
		{"double comma", []string{"role=a,,b"}, "expected a value"},
		{"unknown key", []string{"bogus=1"}, "unknown key"},
		{"key case sensitive", []string{"Type=syscall"}, "unknown key"},
		{"not a number", []string{"roleID=abc"}, "not a uint32"},
		{"overflow", []string{"pid=4294967296"}, "not a uint32"},
		{"negative", []string{"pid=-1"}, "not a uint32"},
		{"prefix on numeric field", []string{"pid~=1"}, "~= is only supported for role"},
		{"bad type", []string{"type=bogus"}, "invalid type"},
		{"bad kind", []string{"kind=bogus"}, "invalid kind"},
		{"missing comparison", []string{"pid 1"}, "expected a comparison operator"},
		{"missing predicate", []string{"pid=1 pid=2"}, "unexpected"},
		{"unclosed parenthesis", []string{"(pid=1"}, "expected ')'"},
		{"stray parenthesis", []string{"pid=1)"}, "unexpected"},
		{"unterminated quote", []string{"role=\"abc"}, "unterminated quoted value"},
		{"not alone", []string{"not"}, "expected a predicate"},
		{"dangling or", []string{"pid=1 ||"}, "expected a predicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseExpr(tt.values)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestParseExprErrorColumn(t *testing.T) {
	_, err := ParseExpr([]string{"pid=1 and"})
	if err == nil {
		t.Fatal("expected an error")
	}
	want := `invalid -e value "pid=1 and": expected a predicate at column 10`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}

	_, err = ParseExpr([]string{"pid 1"})
	if err == nil {
		t.Fatal("expected an error")
	}
	want = `invalid -e value "pid 1": expected a comparison operator at column 5`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestParseExprSourceSizeLimit(t *testing.T) {
	source := "pid=1" + strings.Repeat(" ", maxExprBytes)
	if _, err := ParseExpr([]string{source}); err == nil ||
		!strings.Contains(err.Error(), "4096 bytes") {
		t.Errorf("error = %v, want a size limit error", err)
	}

	exact := "pid=1" + strings.Repeat(" ", maxExprBytes-len("pid=1"))
	if _, err := ParseExpr([]string{exact}); err != nil {
		t.Errorf("ParseExpr at the size limit: %v", err)
	}
}

func TestParseExprNodeLimit(t *testing.T) {
	parts := make([]string, 0, maxExprNodes+1)
	for i := 0; i <= maxExprNodes; i++ {
		parts = append(parts, "pid="+strconv.Itoa(i+1))
	}
	if _, err := ParseExpr([]string{strings.Join(parts, " or ")}); err == nil ||
		!strings.Contains(err.Error(), "nodes") {
		t.Errorf("error = %v, want a node limit error", err)
	}
}

func TestParseExprMergedNodeLimit(t *testing.T) {
	parts := make([]string, 0, 65)
	for i := 0; i < 65; i++ {
		parts = append(parts, "pid="+strconv.Itoa(i+1))
	}
	source := strings.Join(parts, " or ")
	if _, err := ParseExpr([]string{source, source}); err == nil ||
		!strings.Contains(err.Error(), "combine") {
		t.Errorf("error = %v, want a merged node limit error", err)
	}
}

func TestParseExprDepthLimit(t *testing.T) {
	source := strings.Repeat("not ", maxExprDepth) + "pid=1"
	if _, err := ParseExpr([]string{source}); err == nil ||
		!strings.Contains(err.Error(), "depth") {
		t.Errorf("error = %v, want a depth limit error", err)
	}

	allowed := strings.Repeat("not ", maxExprDepth-1) + "pid=1"
	if _, err := ParseExpr([]string{allowed}); err != nil {
		t.Errorf("ParseExpr at the depth limit: %v", err)
	}
}

func TestParseExprAtomValueLimit(t *testing.T) {
	source := "role=" + strings.Repeat("a,", maxAtomValues) + "a"
	if _, err := newExprParser(source).parse(); err == nil ||
		!strings.Contains(err.Error(), "values") {
		t.Errorf("error = %v, want an atom value limit error", err)
	}
}
