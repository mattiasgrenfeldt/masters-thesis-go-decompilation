package golanganalyzerextension.version;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.exceptions.InvalidGolangVersionFormatException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.log.Logger;

public class GolangVersionExtractor {
	private static final String DEFAULT_GO_VERSION="go0.0.0";

	private GolangBinary go_bin;

	private String go_version;

	public GolangVersionExtractor(GolangBinary go_bin) {
		go_version=DEFAULT_GO_VERSION;
		this.go_bin=go_bin;
	}

	public GolangVersion get_go_version() {
		try {
			return new GolangVersion(go_version);
		} catch(InvalidGolangVersionFormatException e) {
			return new GolangVersion(DEFAULT_GO_VERSION);
		}
	}

	public void scan() {
		if(scan_build_info()) {
			return;
		}

		if(scan_sys_the_version()) {
			return;
		}
	}

	private boolean scan_build_info() {
		String tmp_go_version;
		try {
			GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);
			tmp_go_version=go_build_info.get_go_version();
		} catch (InvalidBinaryStructureException e) {
			Logger.append_message(String.format("Failed to scan build info: message=%s", e.getMessage()));
			return false;
		}

		if(!GolangVersion.is_go_version(tmp_go_version)) {
			return false;
		}
		go_version=tmp_go_version;
		return true;
	}

	private boolean scan_sys_the_version() {
		SysTheVersion sys_the_version=new SysTheVersion(go_bin);
		Optional<String> go_version_opt=sys_the_version.get_go_version();
		if(go_version_opt.isEmpty()) {
			return false;
		}
		if(!GolangVersion.is_go_version(go_version_opt.get())) {
			return false;
		}
		go_version=go_version_opt.get();
		return true;
	}

	public static Optional<String> extract_go_version(String data) {
		Pattern p = Pattern.compile(GolangVersion.get_version_pattern());
		Matcher m = p.matcher(data);
		if(m.find()) {
			return Optional.ofNullable(m.group());
		}
		return Optional.empty();
	}
}
