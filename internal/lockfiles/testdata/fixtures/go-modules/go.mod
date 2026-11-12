module example.com/fixture

go 1.22

require (
	example.com/local v0.0.0
	golang.org/x/text v0.14.0
	rsc.io/quote v1.5.2
)

require rsc.io/sampler v1.3.0 // indirect

replace example.com/local => ./local

replace golang.org/x/text v0.14.0 => golang.org/x/text v0.15.0
