
all: return_values return_value_checks

return_values: src/return_values.c
	gcc src/return_values.c -o return_values -g

return_value_checks: src/return_value_checks.c
	gcc src/return_value_checks.c -o return_value_checks -g

clean:
	rm -f return_values return_value_checks

