package utils

import (
	"fmt"
)

func UnitVkFile(n int) string {
	return fmt.Sprintf("unit_%v.vk", n)
}

func UnitPkFile(n int) string {
	return fmt.Sprintf("unit_%v.pk", n)
}

func UnitCcsFile(n int) string {
	return fmt.Sprintf("unit_%v.ccs", n)
}
