import urllib.request
import lzma
import gzip
from collections import namedtuple
from pathlib import Path
# from packaging import version
import operator

AptSource = namedtuple("AptSource", ["archive_type", "url", "dist", "components"])


zip_type = ".gz"


def build_urls(base_url, dist, components, arch="armhf"):
    urls = []
    for component in components:
        url = f"{base_url}dists/{dist}/{component}/binary-{arch}/Packages"
        urls.append(url)
    return urls


def parse_apt_sources_list(sources):
    #lines = sources.split("\n")
    result = []
    for line in sources:
        archive_type, url, dist, *components = line.split(" ")
        if archive_type != "deb":
            continue

        components = list(components)
        result.append(AptSource(archive_type, url, dist, components))
    return result


def get_component_path(component, suffix):
    return Path(component).with_suffix(suffix)


def apt_update(sources):
    for source in sources:
        url = build_urls(source.url, source.dist, source.components)
        for u, c in zip(url, source.components):
            zip_url = u + zip_type
            print(zip_url, get_component_path(c, zip_type))
            urllib.request.urlretrieve(zip_url, get_component_path(c, zip_type))


def build_package_url(base_url, package_url):
    return base_url + package_url


def parse_dependencies(dependency_string):
    result = []
    operators = {
        "<<": operator.lt
        , "<=": operator.le
        , "=": operator.eq
        , ">=": operator.ge
        , ">>": operator.gt
    }
    dependencys = dependency_string.split(",")
    dependencys = [dependency.strip().split("|") for dependency in dependencys]
    # dependencys = [[ for alternative in dependency] for dependency in dependencys]
    for dep in dependencys:
        for alternative in dep:
            split = alternative.strip().split(" ")
            if len(split) > 1:
                package, op, version_number = split
                version_number = version_number[:-1]
                op = op[1:]
                op = operators[op]
            else:
                package = split[0]

            if ":" in package:
                package, arch = package.split(":")
                # print(package, arch)
            else:
                pass
                # print(version.parse(version_number), op)
                # print(package)
            result.append(package)
            break
        # print()
    return result


def get_package_info(selected_package, sources):
    print(f"[APT] getting {selected_package}")
    packages = []
    for source in sources:
        for component in source.components:
            apt_file = get_component_path(component, zip_type)
            tmp = {}
            with gzip.open(apt_file, "r") as f:
                line = f.readline().decode("utf-8")
                while line:
                    if line.strip(" \n\t") == "":
                        if keep:
                            packages.append(tmp)
                            tmp = {}
                    elif line.startswith(" "):
                        if keep:
                            tmp[list(tmp.keys())[-1]] += line
                    else:
                        key, value = line.split(":", 1)
                        value = value.strip()
                        if key.strip() == "Package":
                            keep = (selected_package == value)
                        if keep:
                            tmp[key] = value

                    line = f.readline().decode("utf-8")
                if keep:
                    packages.append(tmp)

    #print(packages)
    assert len(packages) == 1, f"more or less than 1 package found! {len(packages)}"
    package = packages[0]
    package = {k: v.strip() for k, v in package.items()}
    package["Filename"] = build_package_url(source.url, package["Filename"])
    return package


def get_all_deps(dependencies, package):
    package_info = get_package_info(package)
    new_deps = package_info.get("Depends", False)
    if new_deps:
        new_deps = set(parse_dependencies(new_deps))
    else:
        new_deps = set()
    # print(new_deps-dependencies)
    for dep in (new_deps - dependencies):
        print(dep)
        dependencies.add(dep)
        get_all_deps(dependencies, dep)
    return dependencies


def apt_download(package, destination, sources):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)

    package_info = get_package_info(package, sources)
    package_path = Path(destination) / Path(package_info["Filename"]).name
    urllib.request.urlretrieve(package_info["Filename"], package_path)


def main():
    # dep = "python3 (<< 3.8), python3 (>= 3.7~), python3.7:any, python3:any, libblas3 | libblas.so.3, libc6 (>= 2.27), liblapack3 | liblapack.so.3, python3-pkg-resources"
    #
    # parse_dependencies(dep)
    #
    #
    # deps = get_all_deps(set(), "python3-numpy")
    # print(deps)

    repos = ["deb http://raspbian.raspberrypi.org/raspbian/ buster main contrib non-free rpi"]\
        #,
        #     "deb http://archive.raspberrypi.org/debian/ buster main"]
    sources = parse_apt_sources_list(repos)
    apt_download("python3-numpy", "../apt-packages", sources)

    # apt_update(sources)

    # selected_package = "python3"
    # packages = []
    # for source in sources:
    #     for component in source.components:
    #         apt_file = get_componen_path(component)
    #         tmp = {}
    #         with lzma.open(apt_file, "r") as f:
    #             line = f.readline().decode("utf-8")
    #             while line:
    #                 if line.strip(" \n\t") == "":
    #                     if keep:
    #                         packages.append(tmp)
    #                         tmp = {}
    #                 elif line.startswith(" "):
    #                     if keep:
    #                         tmp[list(tmp.keys())[-1]] += line
    #                 else:
    #                     key, value = line.split(":", 1)
    #                     value = value.strip()
    #                     if key.strip() == "Package":
    #                         keep = (selected_package == value)
    #                     if keep:
    #                         tmp[key] = value
    #
    #                 line = f.readline().decode("utf-8")
    #             if keep:
    #                 packages.append(tmp)
    #
    #     print(packages)
    #     assert len(packages) == 1, f"more or less than 1 package found! {len(df)}"
    #     package = packages[0]
    #     package = {k: v.strip() for k, v in package.items()}
    #     print(list(package.keys()))
    #     print(package["Depends"])
    #     print(package["Filename"])
    #     print(source.url)
    #     print(build_package_url(source.url, package["Filename"]))


if __name__ == '__main__':
   main()