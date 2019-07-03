all: apply

docker: docker/Dockerfile
	docker build -t localhost:5000/emojivoto:latest -f docker/Dockerfile docker
	docker push localhost:5000/emojivoto:latest

apply: 
	kubectl apply -f ca.yaml
	sleep 2
	kubectl -n step wait --for=condition=Ready -l app.kubernetes.io/name=step-certificates pod
	kubectl apply -f emojivoto.yaml

delete:
	kubectl delete -f emojivoto.yaml
	kubectl delete -f ca.yaml
