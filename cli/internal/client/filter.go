package client

import (
	"fmt"

	"honeyghost/cli/internal/gen/hng/clisv"
	"honeyghost/cli/internal/model"
)

// toProtoFilter 把 CLI 过滤表达式转换为协议表示；nil 映射为 nil。
//
// 未知的字段、比较方式、逻辑与枚举取值都返回错误，由调用方按内部错误处理。
func toProtoFilter(expr *model.FilterExpr) (*clisv.FilterExpr, error) {
	if expr == nil {
		return nil, nil
	}
	switch expr.Logic {
	case model.FilterLogicAtom:
		if expr.Atom == nil {
			return nil, fmt.Errorf("filter: atom node without a predicate")
		}
		atom, err := toProtoFilterAtom(expr.Atom)
		if err != nil {
			return nil, err
		}
		return &clisv.FilterExpr{Node: &clisv.FilterExpr_Atom{Atom: atom}}, nil

	case model.FilterLogicAnd, model.FilterLogicOr, model.FilterLogicNot:
		if len(expr.Kids) == 0 {
			return nil, fmt.Errorf("filter: logical node without operands")
		}
		if expr.Logic == model.FilterLogicNot && len(expr.Kids) != 1 {
			return nil, fmt.Errorf(
				"filter: not node has %d operands (want 1)", len(expr.Kids))
		}
		logic, err := toProtoFilterLogic(expr.Logic)
		if err != nil {
			return nil, err
		}
		operands := make([]*clisv.FilterExpr, 0, len(expr.Kids))
		for i := range expr.Kids {
			operand, err := toProtoFilter(&expr.Kids[i])
			if err != nil {
				return nil, err
			}
			operands = append(operands, operand)
		}
		return &clisv.FilterExpr{Node: &clisv.FilterExpr_Logic{
			Logic: &clisv.FilterOperands{Logic: logic, Operands: operands},
		}}, nil

	default:
		return nil, fmt.Errorf("filter: unknown logic %d", expr.Logic)
	}
}

func toProtoFilterAtom(atom *model.FilterAtom) (*clisv.FilterAtom, error) {
	field, err := toProtoFilterField(atom.Field)
	if err != nil {
		return nil, err
	}
	compare, err := toProtoFilterCompare(atom.Compare)
	if err != nil {
		return nil, err
	}
	if compare == clisv.FilterCompare_FILTER_COMPARE_PREFIX &&
		atom.Field != model.FilterFieldRoleLabel {
		return nil, fmt.Errorf("filter: prefix comparison is only supported for role")
	}

	out := &clisv.FilterAtom{Field: field, Compare: compare}
	switch atom.Field {
	case model.FilterFieldRoleLabel:
		out.Strings = append([]string(nil), atom.Strings...)
	case model.FilterFieldType:
		for _, eventType := range atom.Types {
			value, err := toProtoEventType(eventType)
			if err != nil {
				return nil, err
			}
			out.Numbers = append(out.Numbers, uint32(value))
		}
	case model.FilterFieldSubtype:
		for _, subtype := range atom.Subtypes {
			value, err := toProtoSubtype(subtype)
			if err != nil {
				return nil, err
			}
			out.Numbers = append(out.Numbers, uint32(value))
		}
	default:
		out.Numbers = append([]uint32(nil), atom.Numbers...)
	}
	if len(out.Numbers) == 0 && len(out.Strings) == 0 {
		return nil, fmt.Errorf("filter: predicate has no values")
	}
	return out, nil
}

func toProtoFilterField(field model.FilterField) (clisv.FilterField, error) {
	switch field {
	case model.FilterFieldType:
		return clisv.FilterField_FILTER_FIELD_TYPE, nil
	case model.FilterFieldSubtype:
		return clisv.FilterField_FILTER_FIELD_SUBTYPE, nil
	case model.FilterFieldPID:
		return clisv.FilterField_FILTER_FIELD_PID, nil
	case model.FilterFieldPPID:
		return clisv.FilterField_FILTER_FIELD_PPID, nil
	case model.FilterFieldRoleID:
		return clisv.FilterField_FILTER_FIELD_ROLE_ID, nil
	case model.FilterFieldRoleLabel:
		return clisv.FilterField_FILTER_FIELD_ROLE_LABEL, nil
	case model.FilterFieldContextID:
		return clisv.FilterField_FILTER_FIELD_CONTEXT_ID, nil
	default:
		return 0, fmt.Errorf("filter: unknown field %d", field)
	}
}

func toProtoFilterCompare(compare model.FilterCompare) (clisv.FilterCompare, error) {
	switch compare {
	case model.FilterCompareEq:
		return clisv.FilterCompare_FILTER_COMPARE_EQ, nil
	case model.FilterCompareNe:
		return clisv.FilterCompare_FILTER_COMPARE_NE, nil
	case model.FilterComparePrefix:
		return clisv.FilterCompare_FILTER_COMPARE_PREFIX, nil
	default:
		return 0, fmt.Errorf("filter: unknown comparison %d", compare)
	}
}

func toProtoFilterLogic(logic model.FilterLogic) (clisv.FilterLogic, error) {
	switch logic {
	case model.FilterLogicAnd:
		return clisv.FilterLogic_FILTER_LOGIC_AND, nil
	case model.FilterLogicOr:
		return clisv.FilterLogic_FILTER_LOGIC_OR, nil
	case model.FilterLogicNot:
		return clisv.FilterLogic_FILTER_LOGIC_NOT, nil
	default:
		return 0, fmt.Errorf("filter: unknown logic %d", logic)
	}
}

func toProtoEventType(eventType model.EventType) (clisv.EventType, error) {
	switch eventType {
	case model.EventTypeSyscall:
		return clisv.EventType_EVENT_TYPE_SYSCALL, nil
	default:
		return 0, fmt.Errorf("unknown event type %q", eventType)
	}
}

func toProtoSubtype(subtype model.Subtype) (clisv.Subtype, error) {
	switch subtype {
	case model.SubtypeProcess:
		return clisv.Subtype_SUBTYPE_PROCESS, nil
	case model.SubtypeExec:
		return clisv.Subtype_SUBTYPE_EXEC, nil
	case model.SubtypeCredential:
		return clisv.Subtype_SUBTYPE_CREDENTIAL, nil
	case model.SubtypeNamespace:
		return clisv.Subtype_SUBTYPE_NAMESPACE, nil
	case model.SubtypeFile:
		return clisv.Subtype_SUBTYPE_FILE, nil
	case model.SubtypeMemory:
		return clisv.Subtype_SUBTYPE_MEMORY, nil
	case model.SubtypeNetwork:
		return clisv.Subtype_SUBTYPE_NETWORK, nil
	case model.SubtypeKernel:
		return clisv.Subtype_SUBTYPE_KERNEL, nil
	default:
		return 0, fmt.Errorf("unknown event subtype %q", subtype)
	}
}
