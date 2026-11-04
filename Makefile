.PHONY: images deploy destroy test-basic test-images test-topology test-matrix test-proxy test-web test-waf test-ids test-siem test-attacks test-all

TESTS := test-images test-topology test-matrix test-proxy test-waf test-ids test-siem test-web test-attacks

images:
	bash scripts/build-images.sh

deploy: images
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

test-basic:
	containerlab deploy -t topology/basicTest.clab.yml
	docker exec clab-basicTest-a ping -c 2 10.0.0.2
	containerlab destroy -t topology/basicTest.clab.yml --cleanup

test-web:
	bash tests/test-web.sh

test-waf:
	bash tests/test-waf.sh

test-siem:
	bash tests/test-siem.sh

test-attacks:
	bash tests/test-attacks.sh

test-all:
	@[ -n "$(TESTS)" ] || { echo "TESTS is empty"; exit 1; }
	@failed=""; \
	for t in $(TESTS); do \
	  echo "######## $$t"; \
	  $(MAKE) --no-print-directory $$t || failed="$$failed $$t"; \
	done; \
	if [ -n "$$failed" ]; then echo "FAILED:$$failed"; exit 1; else echo "ALL TESTS PASSED"; fi
