# Define backup go macros
%if %{rhel} == 8
%global gopkg %package -n %{goname}-devel \
Summary:	%{summary} \
BuildArch:  noarch \
%description -n %{goname}-devel \
%{common_description}
%global goprep(A) %setup -q
%global generate_buildrequires echo "Need more specific macro on rhel8"
%global gopkginstall for file in $(find . -iname "*.go" \! -iname "*_test.go" \! -iname "main.go" ) ; do \
    echo "%%dir %%{gopath}/src/%%{goipath}/$(dirname $file)" >> devel.file-list ;\
    install -d -p %{buildroot}/%{gopath}/src/%{goipath}/$(dirname $file) ;\
    cp -pav $file %{buildroot}/%{gopath}/src/%{goipath}/$file ;\
    echo "%%{gopath}/src/%%{goipath}/$file" >> devel.file-list ;\
done ;\
sort -u -o devel.file-list devel.file-list
%global gopkgfiles %files -n %{goname}-devel -f devel.file-list
%global gocheck echo "skipping gocheck on rhel8"
# Specific BuildRequires macro
%global go_generate_buildrequires BuildRequires:	%{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}
%endif

%global debug_package %{nil}
# https://github.com/farsightsec/golang-framestream
%global goipath         github.com/farsightsec/golang-framestream
%global common_description %{expand:
A lightweight, binary-clean protocol that allows for the transport of arbitrarily encoded data payload sequences with minimal framing overhead.}

#Name:           golang-framestream
Version:        0.3.0
Release:        1%{?dist}
Summary:        Framestream protocol Golang implementation
%gometa
Name:           %{goname}
License:        Apache-2.0
URL:            %{gourl}
Source0:        %{gosource}
%global golicenses      LICENSE
%global godocs          README.md

%description
%{common_description}

%package -n %{goname}-devel
Summary:	%{summary}
BuildArch:  noarch
%description -n %{goname}-devel
%{common_description}

%go_generate_buildrequires

%gopkg

%prep
%goprep -A

%install
%gopkginstall

%if %{with check}
%check
%gocheck
%endif

%gopkgfiles

%changelog
