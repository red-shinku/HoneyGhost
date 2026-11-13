package client

import (
	"reflect"
	"strings"
	"testing"

	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

func protoAtom(field clisv.FilterField, compare clisv.FilterCompare,
	numbers []uint32, labels []string) *clisv.FilterExpr {
	return &clisv.FilterExpr{Node: &clisv.FilterExpr_Atom{Atom: &clisv.FilterAtom{
		Field: field, Compare: compare, Numbers: numbers, Strings: labels,
	}}}
}

func protoLogic(logic clisv.FilterLogic, operands ...*clisv.FilterExpr) *clisv.FilterExpr {
	return &clisv.FilterExpr{Node: &clisv.FilterExpr_Logic{
		Logic: &clisv.FilterOperands{Logic: logic, Operands: operands},
	}}
}

func TestToProtoFilterNil(t *testing.T) {
	got, err := toProtoFilter(nil)
	if err != nil {
		t.Fatalf("toProtoFilter(nil): %v", err)
	}
	if got != nil {
		t.Errorf("toProtoFilter(nil) = %+v, want nil", got)
	}
}

func TestToProtoFilterAtom(t *testing.T) {
	tests := []struct {
		name string
		atom *model.FilterAtom
		want *clisv.FilterAtom
	}{
		{
			name: "type",
			atom: &model.FilterAtom{
				Field: model.FilterFieldType, Compare: model.FilterCompareEq,
				Types: []model.EventType{model.EventTypeSyscall, model.EventTypeFile},
			},
			want: &clisv.FilterAtom{
				Field:   clisv.FilterField_FILTER_FIELD_TYPE,
				Compare: clisv.FilterCompare_FILTER_COMPARE_EQ,
				Numbers: []uint32{
					uint32(clisv.EventType_EVENT_TYPE_SYSCALL),
					uint32(clisv.EventType_EVENT_TYPE_FILE),
				},
			},
		},
		{
			name: "kind not in",
			atom: &model.FilterAtom{
				Field: model.FilterFieldKind, Compare: model.FilterCompareNe,
				Kinds: []model.EventKind{model.EventKindExec, model.EventKindKernel},
			},
			want: &clisv.FilterAtom{
				Field:   clisv.FilterField_FILTER_FIELD_KIND,
				Compare: clisv.FilterCompare_FILTER_COMPARE_NE,
				Numbers: []uint32{
					uint32(clisv.EventKind_EVENT_KIND_EXEC),
					uint32(clisv.EventKind_EVENT_KIND_KERNEL),
				},
			},
		},
		{
			name: "pid",
			atom: &model.FilterAtom{
				Field: model.FilterFieldPID, Compare: model.FilterCompareEq,
				Numbers: []uint32{1, 2},
			},
			want: &clisv.FilterAtom{
				Field:   clisv.FilterField_FILTER_FIELD_PID,
				Compare: clisv.FilterCompare_FILTER_COMPARE_EQ,
				Numbers: []uint32{1, 2},
			},
		},
		{
			name: "ppid zero",
			atom: &model.FilterAtom{
				Field: model.FilterFieldPPID, Compare: model.FilterCompareEq,
				Numbers: []uint32{0},
			},
			want: &clisv.FilterAtom{
				Field:   clisv.FilterField_FILTER_FIELD_PPID,
				Compare: clisv.FilterCompare_FILTER_COMPARE_EQ,
				Numbers: []uint32{0},
			},
		},
		{
			name: "role id zero",
			atom: &model.FilterAtom{
				Field: model.FilterFieldRoleID, Compare: model.FilterCompareEq,
				Numbers: []uint32{0, 7},
			},
			want: &clisv.FilterAtom{
				Field:   clisv.FilterField_FILTER_FIELD_ROLE_ID,
				Compare: clisv.FilterCompare_FILTER_COMPARE_EQ,
				Numbers: []uint32{0, 7},
			},
		},
		{
			name: "context id",
			atom: &model.FilterAtom{
				Field: model.FilterFieldContextID, Compare: model.FilterCompareEq,
				Numbers: []uint32{0},
			},
			want: &clisv.FilterAtom{
				Field:   clisv.FilterField_FILTER_FIELD_CONTEXT_ID,
				Compare: clisv.FilterCompare_FILTER_COMPARE_EQ,
				Numbers: []uint32{0},
			},
		},
		{
			name: "role labels",
			atom: &model.FilterAtom{
				Field: model.FilterFieldRoleLabel, Compare: model.FilterCompareEq,
				Strings: []string{"a", "b"},
			},
			want: &clisv.FilterAtom{
				Field:   clisv.FilterField_FILTER_FIELD_ROLE_LABEL,
				Compare: clisv.FilterCompare_FILTER_COMPARE_EQ,
				Strings: []string{"a", "b"},
			},
		},
		{
			name: "role prefix",
			atom: &model.FilterAtom{
				Field: model.FilterFieldRoleLabel, Compare: model.FilterComparePrefix,
				Strings: []string{"registry/"},
			},
			want: &clisv.FilterAtom{
				Field:   clisv.FilterField_FILTER_FIELD_ROLE_LABEL,
				Compare: clisv.FilterCompare_FILTER_COMPARE_PREFIX,
				Strings: []string{"registry/"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toProtoFilter(&model.FilterExpr{Atom: tt.atom})
			if err != nil {
				t.Fatalf("toProtoFilter: %v", err)
			}
			if msg := got.GetAtom(); !reflect.DeepEqual(msg, tt.want) {
				t.Errorf("atom = %v, want %v", msg, tt.want)
			}
		})
	}
}

func TestToProtoFilterNested(t *testing.T) {
	expr := &model.FilterExpr{
		Logic: model.FilterLogicAnd,
		Kids: []model.FilterExpr{
			{Atom: &model.FilterAtom{
				Field: model.FilterFieldPID, Compare: model.FilterCompareEq,
				Numbers: []uint32{1},
			}},
			{Logic: model.FilterLogicOr, Kids: []model.FilterExpr{
				{Atom: &model.FilterAtom{
					Field: model.FilterFieldType, Compare: model.FilterCompareEq,
					Types: []model.EventType{model.EventTypeFile},
				}},
				{Atom: &model.FilterAtom{
					Field: model.FilterFieldKind, Compare: model.FilterCompareEq,
					Kinds: []model.EventKind{model.EventKindExec},
				}},
			}},
			{Logic: model.FilterLogicNot, Kids: []model.FilterExpr{
				{Atom: &model.FilterAtom{
					Field: model.FilterFieldRoleLabel, Compare: model.FilterComparePrefix,
					Strings: []string{"registry/"},
				}},
			}},
		},
	}
	want := protoLogic(clisv.FilterLogic_FILTER_LOGIC_AND,
		protoAtom(clisv.FilterField_FILTER_FIELD_PID,
			clisv.FilterCompare_FILTER_COMPARE_EQ, []uint32{1}, nil),
		protoLogic(clisv.FilterLogic_FILTER_LOGIC_OR,
			protoAtom(clisv.FilterField_FILTER_FIELD_TYPE,
				clisv.FilterCompare_FILTER_COMPARE_EQ,
				[]uint32{uint32(clisv.EventType_EVENT_TYPE_FILE)}, nil),
			protoAtom(clisv.FilterField_FILTER_FIELD_KIND,
				clisv.FilterCompare_FILTER_COMPARE_EQ,
				[]uint32{uint32(clisv.EventKind_EVENT_KIND_EXEC)}, nil)),
		protoLogic(clisv.FilterLogic_FILTER_LOGIC_NOT,
			protoAtom(clisv.FilterField_FILTER_FIELD_ROLE_LABEL,
				clisv.FilterCompare_FILTER_COMPARE_PREFIX, nil, []string{"registry/"})))

	got, err := toProtoFilter(expr)
	if err != nil {
		t.Fatalf("toProtoFilter: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("toProtoFilter = %#v, want %#v", got, want)
	}
}

func TestToProtoFilterErrors(t *testing.T) {
	tests := []struct {
		name string
		expr *model.FilterExpr
		want string
	}{
		{
			name: "atom without predicate",
			expr: &model.FilterExpr{},
			want: "atom node without a predicate",
		},
		{
			name: "unknown field",
			expr: &model.FilterExpr{Atom: &model.FilterAtom{
				Field: model.FilterField(99), Compare: model.FilterCompareEq,
				Numbers: []uint32{1},
			}},
			want: "unknown field",
		},
		{
			name: "unknown comparison",
			expr: &model.FilterExpr{Atom: &model.FilterAtom{
				Field: model.FilterFieldPID, Compare: model.FilterCompare(99),
				Numbers: []uint32{1},
			}},
			want: "unknown comparison",
		},
		{
			name: "unknown logic",
			expr: &model.FilterExpr{Logic: model.FilterLogic(99)},
			want: "unknown logic",
		},
		{
			name: "logical node without operands",
			expr: &model.FilterExpr{Logic: model.FilterLogicAnd},
			want: "without operands",
		},
		{
			name: "not with two operands",
			expr: &model.FilterExpr{Logic: model.FilterLogicNot, Kids: []model.FilterExpr{
				{Atom: &model.FilterAtom{
					Field: model.FilterFieldPID, Compare: model.FilterCompareEq,
					Numbers: []uint32{1},
				}},
				{Atom: &model.FilterAtom{
					Field: model.FilterFieldPID, Compare: model.FilterCompareEq,
					Numbers: []uint32{2},
				}},
			}},
			want: "want 1",
		},
		{
			name: "unknown event type",
			expr: &model.FilterExpr{Atom: &model.FilterAtom{
				Field: model.FilterFieldType, Compare: model.FilterCompareEq,
				Types: []model.EventType{"bogus"},
			}},
			want: "unknown event type",
		},
		{
			name: "unknown event kind",
			expr: &model.FilterExpr{Atom: &model.FilterAtom{
				Field: model.FilterFieldKind, Compare: model.FilterCompareEq,
				Kinds: []model.EventKind{"bogus"},
			}},
			want: "unknown event kind",
		},
		{
			name: "prefix on numeric field",
			expr: &model.FilterExpr{Atom: &model.FilterAtom{
				Field: model.FilterFieldPID, Compare: model.FilterComparePrefix,
				Numbers: []uint32{1},
			}},
			want: "only supported for role",
		},
		{
			name: "predicate without values",
			expr: &model.FilterExpr{Atom: &model.FilterAtom{
				Field: model.FilterFieldPID, Compare: model.FilterCompareEq,
			}},
			want: "no values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := toProtoFilter(tt.expr); err == nil ||
				!strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
