deploy:
	containerlab deploy -t topology/smoke.clab.yml

destroy:
	containerlab destroy -t topology/smoke.clab.yml --cleanup

test:
	docker exec clab-smoke-a ping -c 2 10.0.0.2