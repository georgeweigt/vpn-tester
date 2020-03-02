#include "defs.h"

#define MLENGTH(u) (u)[-1]

// returns (a ** b) mod c

unsigned *
modpow(unsigned *a, unsigned *b, unsigned *c)
{
	unsigned *t, *y;
	a = mcopy(a);
	b = mcopy(b);
	// y = 1
	y = mnew(1);
	y[0] = 1;
	for (;;) {
		if (b[0] & 1) {
			// y = (y * a) mod c
			t = mmul(y, a);
			mfree(y);
			y = t;
			mmod(y, c);
		}
		// b = b >> 1
		mshr(b);
		// b = 0?
		if (MLENGTH(b) == 1 && b[0] == 0)
			break;
		// a = (a * a) mod c
		t = mmul(a, a);
		mfree(a);
		a = t;
		mmod(a, c);
	}
	mfree(a);
	mfree(b);
	return y;
}

// returns u + v

unsigned *
madd(unsigned *u, unsigned *v)
{
	int i, n, nu, nv, nw;
	unsigned long long t;
	unsigned *w;
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	if (nu > nv)
		nw = nu + 1;
	else
		nw = nv + 1;
	w = mnew(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (unsigned long long) w[i] + v[i];
		w[i] = t;
		t >>= 32;
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t >>= 32;
	}
	mnorm(w);
	return w;
}

// returns u - v

unsigned *
msub(unsigned *u, unsigned *v)
{
	int i, nu, nv, nw;
	unsigned long long t;
	unsigned *w;
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	if (nu > nv)
		nw = nu;
	else
		nw = nv;
	w = mnew(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (unsigned long long) w[i] - v[i];
		w[i] = t;
		t = (long long) t >> 32; // cast to extend sign
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t = (long long) t >> 32; // cast to extend sign
	}
	mnorm(w);
	return w;
}

// returns u * v

unsigned *
mmul(unsigned *u, unsigned *v)
{
	int i, j, nu, nv, nw;
	unsigned long long t;
	unsigned *w;
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	nw = nu + nv;
	w = mnew(nw);
	for (i = 0; i < nu; i++)
		w[i] = 0;
	for (j = 0; j < nv; j++) {
		t = 0;
		for (i = 0; i < nu; i++) {
			t += (unsigned long long) u[i] * v[j] + w[i + j];
			w[i + j] = t;
			t >>= 32;
		}
		w[i + j] = t;
	}
	mnorm(w);
	return w;
}

// returns floor(u / v)

unsigned *
mdiv(unsigned *u, unsigned *v)
{
	int i, k, nu, nv;
	unsigned *q, qhat, *w;
	unsigned long long a, b, t;
	mnorm(u);
	mnorm(v);
	if (MLENGTH(v) == 1 && v[0] == 0)
		return NULL; // v = 0
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	k = nu - nv;
	if (k < 0) {
		q = mnew(1);
		q[0] = 0;
		return q; // u < v, return zero
	}
	u = mcopy(u);
	q = mnew(k + 1);
	w = mnew(nv + 1);
	b = v[nv - 1];
	do {
		q[k] = 0;
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (unsigned long long) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (unsigned long long) u[i] - w[i - k];
				u[i] = t;
				t = (long long) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (unsigned long long) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			q[k] += qhat;
			mnorm(u);
			nu = MLENGTH(u);
		}
	} while (--k >= 0);
	mnorm(q);
	mfree(u);
	mfree(w);
	return q;
}

// u = u mod v

void
mmod(unsigned *u, unsigned *v)
{
	int i, k, nu, nv;
	unsigned qhat, *w;
	unsigned long long a, b, t;
	mnorm(u);
	mnorm(v);
	if (MLENGTH(v) == 1 && v[0] == 0)
		return; // v = 0
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	k = nu - nv;
	if (k < 0)
		return; // u < v
	w = mnew(nv + 1);
	b = v[nv - 1];
	do {
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (unsigned long long) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (unsigned long long) u[i] - w[i - k];
				u[i] = t;
				t = (long long) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (unsigned long long) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			mnorm(u);
			nu = MLENGTH(u);
		}
	} while (--k >= 0);
	mfree(w);
}

// returns u ** v

unsigned *
mpow(unsigned *u, unsigned *v)
{
	unsigned *t, *w;
	u = mcopy(u);
	v = mcopy(v);
	// w = 1
	w = mnew(1);
	w[0] = 1;
	for (;;) {
		if (v[0] & 1) {
			// w = w * u
			t = mmul(w, u);
			mfree(w);
			w = t;
		}
		// v = v >> 1
		mshr(v);
		// v = 0?
		if (MLENGTH(v) == 1 && v[0] == 0)
			break;
		// u = u * u
		t = mmul(u, u);
		mfree(u);
		u = t;
	}
	mfree(u);
	mfree(v);
	return w;
}

// u = u >> 1

void
mshr(unsigned *u)
{
	int i;
	for (i = 0; i < MLENGTH(u) - 1; i++) {
		u[i] >>= 1;
		if (u[i + 1] & 1)
			u[i] |= 0x80000000;
	}
	u[i] >>= 1;
	mnorm(u);
}

// compare u and v

int
mcmp(unsigned *u, unsigned *v)
{
	int i;
	mnorm(u);
	mnorm(v);
	if (MLENGTH(u) < MLENGTH(v))
		return -1;
	if (MLENGTH(u) > MLENGTH(v))
		return 1;
	for (i = MLENGTH(u) - 1; i >= 0; i--) {
		if (u[i] < v[i])
			return -1;
		if (u[i] > v[i])
			return 1;
	}
	return 0; // u = v
}

unsigned *
mnew(int n)
{
	unsigned *u;
	u = (unsigned *) malloc((n + 1) * sizeof (unsigned));
	if (u == NULL) {
		printf("malloc kaput\n");
		exit(1);
	}
	*u = n;
	return u + 1;
}

void
mfree(unsigned *u)
{
	free(u - 1);
}

unsigned *
mcopy(unsigned *u)
{
	int i;
	unsigned *v;
	v = mnew(MLENGTH(u));
	for (i = 0; i < MLENGTH(u); i++)
		v[i] = u[i];
	return v;
}

// remove leading zeroes

void
mnorm(unsigned *u)
{
	while (MLENGTH(u) > 1 && u[MLENGTH(u) - 1] == 0)
		MLENGTH(u)--;
}
