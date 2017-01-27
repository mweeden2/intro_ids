
public class Hole {
	
	private int first;
	private int last;
	
	// default constructor creates the largest hole possible
	Hole() {
		this.first = 0;
		this.last = 65535;
	}
	Hole(int f, int l) {
		this.first = f;
		this.last = l;
	}
	public int getFirst() {
		return first;
	}
	public void setFirst(int first) {
		this.first = first;
	}
	public int getLast() {
		return last;
	}
	public void setLast(int last) {
		this.last = last;
	}
}
