//go:build crosed && crosed_l3 && !crosed_l4 && !crosed_l5

package main

func compiledCrosedLevel() int { return 3 }
