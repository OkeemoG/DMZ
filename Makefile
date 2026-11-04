.PHONY: images pki deploy destroy test-basic test-images test-topology test-matrix test-proxy test-web test-waf test-ids test-vpn test-all

TESTS := test-images test-topology test-matrix test-proxy test-waf test-ids test-web test-vpn

images:
	bash scripts/build-images.sh

pki: images
	bash scripts/gen-vpn-pki.sh

deploy: images pki
	containerlab deploy -t topology/dmz.clab.yml --reconfigure

destroy:
	containerlab destroy -t topology/dmz.clab.yml --cleanup

test-images:
	bash tests/test-images.sh

test-topology:
	bash tests/test-topology.sh

test-matrix:
	bash tests/test-matrix.sh

test-proxy:
	bash tests/test-proxy.sh

test-ids:
	bash tests/test-ids.sh

test-vpn:
	bash tests/test-vpn.sh

test-basic:
	containerlab deploy -t topology/basicTest.clab.yml
	docker exec clab-basicTest-a ping -c 2 10.0.0.2
	containerlab destroy -t topology/basicTest.clab.yml --cleanup

test-web:
	bash tests/test-web.sh

test-waf:
	bash tests/test-waf.sh

test-all:
	@[ -n "$(TESTS)" ] || { echo "TESTS is empty"; exit 1; }
	@failed=""; \
	for t in $(TESTS); do \
	  echo "######## $$t"; \
	  $(MAKE) --no-print-directory $$t || failed="$$failed $$t"; \
	done; \
	if [ -n "$$failed" ]; then echo "FAILED:$$failed"; exit 1; else echo "ALL TESTS PASSED"; fi