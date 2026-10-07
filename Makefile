test:
	containerlab deploy -t topology/smoke.clab.yml
	docker exec clab-smoke-a ping -c 2 10.0.0.2
	containerlab destroy -t topology/smoke.clab.yml --cleanup
