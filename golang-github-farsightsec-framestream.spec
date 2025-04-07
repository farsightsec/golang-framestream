%global debug_package %{nil}

# https://github.com/farsightsec/golang-framestream
%global goipath         github.com/farsightsec/golang-framestream
Version:                0.3.0

%gometa

%global common_description %{expand:
A lightweight, binary-clean protocol that allows for the transport of arbitrarily encoded data payload sequences with minimal framing overhead.}

%global golicenses      LICENSE
%global godocs          README.md

#Name:           %{goname}
Name:           golang-github-farsightsec-framestream
Release:        1%{?dist}
Summary:        Framestream protocol Golang implementation

License:        Apache-2.0
URL:            %{gourl}
Source:         https://%{provider_prefix}/archive/%{commit}/%{name}-%{version}.tar.gz
BuildRequires:  mock-rpmautospec rpmautospec

#%package -n golang-github-farsightsec-golang-framestream
#Summary:        Framestream protocol Golang implementation Binary Package

%description
#This next line seems to fail when using the package macro
%{common_description}

%gopkg

%prep
%goprep

%generate_buildrequires
%go_generate_buildrequires

%install
%gopkginstall

%if %{with check}
%check
%gocheck
%endif

%gopkgfiles

%changelog
%autochangelog
