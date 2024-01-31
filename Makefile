bootstrap:
# Initialize submodules
	git submodule update --init
# Initialize sparse checkout in the `web5-spec` submodule
	git -C Tests/Web5TestVectors/web5-spec config core.sparseCheckout true
# Sparse checkout only the `test-vectors` directory from `web5-spec`
	git -C Tests/Web5TestVectors/web5-spec sparse-checkout set test-vectors
# Update submodules so they sparse checkout takes effect
	git submodule update
format:
	swift format --in-place --recursive .
