/*
 * Copyright (c) 2015-2018, Pelayo Bernedo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
