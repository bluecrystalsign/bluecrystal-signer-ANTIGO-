package bluecrystal.domain;

public class NameValue {
	private String name;
	private String value;
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}
	public NameValue() {
		super();
		// TODO Auto-generated constructor stub
	}
	public NameValue(String name, String value) {
		super();
		this.name = name;
		this.value = value;
	}

}
