package main

import "reflect"

// merge returns a copy of base with the entries of each extra map added.
func merge(base M, extra ...M) M {
	m := M{}
	for _, e := range append([]M{base}, extra...) {
		for k, v := range e {
			m[k] = v
		}
	}
	return m
}

// find returns the value at the first place in res where the keys appear as
// a path, searching nested objects and arrays depth-first.
func find(v any, path ...string) any {
	switch x := v.(type) {
	case M:
		if got, ok := x[path[0]]; ok {
			if len(path) == 1 {
				return got
			}
			if r := find(got, path[1:]...); r != nil {
				return r
			}
		}
		for _, k := range sortedKeys(x) {
			if r := find(x[k], path...); r != nil {
				return r
			}
		}
	default:
		if rv := reflect.ValueOf(v); rv.Kind() == reflect.Slice {
			for i := 0; i < rv.Len(); i++ {
				if r := find(rv.Index(i).Interface(), path...); r != nil {
					return r
				}
			}
		}
	}
	return nil
}
