#include <iostream>
#include <iomanip>
#include <math.h>

enum { wi = 9 };

void show_time(double secs)
{
	if (secs < 60) {
		std::cout << std::setw(wi) << secs << " seconds ";
		return;
	}
	double t = secs/60;
	if (t < 60) {
		std::cout << std::setw(wi) << t << " minutes ";
		return;
	}
	t /= 60;
	if (t < 24) {
		std::cout << std::setw(wi) << t << " hours   ";
		return;
	}
	t /= 24;
	if (t < 31) {
		std::cout << std::setw(wi) << t << " days    ";
		return;
	}
	if (t < 365) {
		std::cout << std::setw(wi) << t/30.5 << " months  ";
		return;
	}
	t /= 365;
	if (t < 1000) {
		std::cout << std::setw(wi) << t << " years   ";
		return;
	}
	t /= 1000;
	if (t < 1000) {
		std::cout << std::setw(wi) << t << " kyears  ";
		return;
	}
	t /= 1000;
	if (t < 1000) {
		std::cout << std::setw(wi) << t << " Myears  ";
	} else {
		std::cout << std::setw(wi) << t/1000 << " Gyears  ";
	}
}


int main()
{
	std::cout << "Assuming completely random letters and digits, without case sensitivity\n"
			  << "at 10⁶, 10⁹, 10¹², 10¹⁶ attempts per second.\n";
	std::cout << std::setprecision(1) << std::fixed;
	for (int i = 5; i < 21; ++i) {
		double combs = pow(2, i*5)/2;
		std::cout << std::setw(2) << i << " letters: ";
		std::cout << i * 5 << " bits  ";
		show_time (combs/1e6);
		std::cout << "    ";
		show_time (combs/1e9);
		std::cout << "    ";
		show_time (combs/1e12);
		std::cout << "    ";
		show_time (combs/1e16);
		std::cout << '\n';
	}
}
