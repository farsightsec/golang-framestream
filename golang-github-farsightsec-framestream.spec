%global debug_package %{nil}

# https://github.com/farsightsec/golang-framestream
%global goipath         github.com/farsightsec/golang-framestream
Version:                0.3.0

%gometa

%global common_description %{expand:
A lightweight, binary-clean protocol that allows for the transport of arbitrarily encoded data payload sequences with minimal framing overhead.}

%global golicenses      LICENSE
%global godocs          README.md

Name:           golang-framestream
Release:        1%{?dist}
Summary:        Framestream protocol Golang implementation

License:        Apache-2.0
URL:            %{gourl}
Source:         https://%{provider_prefix}/archive/%{commit}/%{name}-%{version}.tar.gz

%description
%{common_description}

%package -n %{goname}-devel
Summary:	%{summary}
BuildArch:  noarch
%description -n %{goname}-devel
%{common_description}

%prep
%setup -q

%install
install -d -p %{buildroot}/%{gopath}/src/%{import_path}/
for file in $(find . -iname "*.go" \! -iname "*_test.go" \! -iname "main.go" ) ; do
    echo "%%dir %%{gopath}/src/%%{import_path}/$(dirname $file)" >> devel.file-list
    install -d -p %{buildroot}/%{gopath}/src/%{import_path}/$(dirname $file)
    cp -pav $file %{buildroot}/%{gopath}/src/%{import_path}/$file
    echo "%%{gopath}/src/%%{import_path}/$file" >> devel.file-list
done

# source codes for building projects
install -d -p %{buildroot}/%{gopath}/src/%{import_path}/
echo "%%dir %%{gopath}/src/%%{import_path}/." >> devel.file-list
# find all *.s and generate devel.file-list
for file in $(find . -iname "*.s") ; do
    echo "%%dir %%{gopath}/src/%%{import_path}/$(dirname $file)" >> devel.file-list
    install -d -p %{buildroot}/%{gopath}/src/%{import_path}/$(dirname $file)
    cp -pav $file %{buildroot}/%{gopath}/src/%{import_path}/$file
    echo "%%{gopath}/src/%%{import_path}/$file" >> devel.file-list
done
# find all *.c and generate devel.file-list
for file in $(find . -iname "*.c") ; do
    echo "%%dir %%{gopath}/src/%%{import_path}/$(dirname $file)" >> devel.file-list
    install -d -p %{buildroot}/%{gopath}/src/%{import_path}/$(dirname $file)
    cp -pav $file %{buildroot}/%{gopath}/src/%{import_path}/$file
    echo "%%{gopath}/src/%%{import_path}/$file" >> devel.file-list
done
# find all *.go but no *_test.go files and generate devel.file-list
for file in $(find . -iname "*.go" \! -iname "*_test.go") ; do
    echo "%%dir %%{gopath}/src/%%{import_path}/$(dirname $file)" >> devel.file-list
    install -d -p %{buildroot}/%{gopath}/src/%{import_path}/$(dirname $file)
    cp -pav $file %{buildroot}/%{gopath}/src/%{import_path}/$file
    echo "%%{gopath}/src/%%{import_path}/$file" >> devel.file-list
done
sort -u -o devel.file-list devel.file-list
install -m 0755 -vd %{buildroot}%{gopath}/src/%(dirname %{oldgoipath})

%if %{rhel} != 8
%if %{with check}
%check
%gocheck
%endif
%endif

%files -n %{goname}-devel -f devel.file-list

%changelog
