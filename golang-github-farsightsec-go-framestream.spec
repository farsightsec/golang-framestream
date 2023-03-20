
# this is code only
%global debug_package   %{nil}

%global provider        github
%global provider_tld    com
%global project       	farsightsec
%global repo            golang-framestream
# https://github.com/farsightsec/golang-framestream/
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          8a0cb8ba87105c2d27e725e48e50ce0b5c521d57
%global shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           golang-github-farsightsec-go-framestream-devel
Version:        0.1.0
Release:        1%{?dist}
Summary:        Frame Streams implementation in Go

License:        Apache-2.0
URL:            https://%{provider_prefix}
# using github generated tarball for now
Source0:        https://%{provider_prefix}/archive/%{commit}/%{repo}-%{shortcommit}.tar.gz

BuildRequires:  %{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}

%description
%{summary}

Frame Streams is a lightweight, binary-clean protocol that allows
for the transport of arbitrarily encoded data payload sequences with
minimal framing overhead.

This provides the Golang development code of Frame Streams.

%prep
%setup -q -n %{repo}-%{commit}

%build

# installs source code for building other projects
# find all *.go but no *_test.go files and generate file-list
# and no framestream_dump/main.go
%install
#rm -rf $RPM_BUILD_ROOT
install -d -p %{buildroot}/%{gopath}/src/%{import_path}/
for file in $(find . -iname "*.go" \! -iname "*_test.go" \! -iname "main.go" ) ; do
    echo "%%dir %%{gopath}/src/%%{import_path}/$(dirname $file)" >> file-list
    install -d -p %{buildroot}/%{gopath}/src/%{import_path}/$(dirname $file)
    cp -pav $file %{buildroot}/%{gopath}/src/%{import_path}/$file
    echo "%%{gopath}/src/%%{import_path}/$file" >> file-list
done
sort -u -o file-list file-list

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

%files -f file-list
%license LICENSE COPYRIGHT
%doc README.md
%dir %{gopath}/src/%{provider}.%{provider_tld}/%{project}

%changelog
