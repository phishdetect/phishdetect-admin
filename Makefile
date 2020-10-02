.DEFAULT_GOAL = dist
PWD = $(shell pwd)

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/*.egg-info

css:
	cp node_modules/tailwindcss/dist/tailwind.min.css phishdetectadmin/css/
	./node_modules/.bin/tailwind build phishdetectadmin/css/main.css -o phishdetectadmin/css/main.dist.css

dist:css
	python3 setup.py sdist bdist_wheel

upload:
	python3 -m twine upload dist/*
