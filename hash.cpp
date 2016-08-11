#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string>

using std::string;

typedef void HASHFREE(void *);
typedef int HASHCMP(const void *, const void *);
typedef unsigned int HASHHASH(const void *, unsigned int);
typedef struct _hash_link hash_link;
typedef struct _hash_table hash_table;

struct _hash_link {
    void *key;
    void* val;
    hash_link *next;
};

struct _hash_table {
    hash_link **buckets;
    HASHCMP *cmp;
    HASHHASH *hash;
    unsigned int size;
    unsigned int current_slot;
    hash_link *next;
    int count;
};

hash_table *hash_create(HASHCMP *, int, HASHHASH *);
void hash_join(hash_table *, hash_link *);
void hash_remove_link(hash_table *, hash_link *);
int hashPrime(int n);
hash_link *hash_lookup(hash_table *, const void *);
void hash_first(hash_table *);
hash_link *hash_next(hash_table *);
void hash_last(hash_table *);
hash_link *hash_get_bucket(hash_table *, unsigned int);
void hashFreeMemory(hash_table *);
void hashFreeItems(hash_table *, HASHFREE *);
HASHHASH hash_string;
HASHHASH hash4;
const char *hashKeyStr(hash_link *);

#define  DEFAULT_HASH_SIZE 7951	/* prime number < 8192 */

static void hash_next_bucket(hash_table * hid);

unsigned int
hash_string(const void *data, unsigned int size)
{
    const char *s = (char*)const_cast<void*>(data);
    unsigned int n = 0;
    unsigned int j = 0;
    unsigned int i = 0;
    while (*s) {
	j++;
	n ^= 271 * (unsigned) *s++;
    }
    i = n ^ (j * 271);
    return i % size;
}

/* the following function(s) were adapted from
 *    usr/src/lib/libc/db/hash_func.c, 4.4 BSD lite */

/* Hash function from Chris Torek. */
unsigned int
hash4(const void *data, unsigned int size)
{
    const char *key = (char*)const_cast<void*>(data);
    size_t loop;
    unsigned int h;
    size_t len;

#define HASH4a   h = (h << 5) - h + *key++;
#define HASH4b   h = (h << 5) + h + *key++;
#define HASH4 HASH4b

    h = 0;
    len = strlen(key);
    loop = len >> 3;
    switch (len & (8 - 1)) {
    case 0:
	break;
    case 7:
	HASH4;
	/* FALLTHROUGH */
    case 6:
	HASH4;
	/* FALLTHROUGH */
    case 5:
	HASH4;
	/* FALLTHROUGH */
    case 4:
	HASH4;
	/* FALLTHROUGH */
    case 3:
	HASH4;
	/* FALLTHROUGH */
    case 2:
	HASH4;
	/* FALLTHROUGH */
    case 1:
	HASH4;
    }
    while (loop--) {
	HASH4;
	HASH4;
	HASH4;
	HASH4;
	HASH4;
	HASH4;
	HASH4;
	HASH4;
    }
    return h % size;
}

/*
 *  hash_create - creates a new hash table, uses the cmp_func
 *  to compare keys.  Returns the identification for the hash table;
 *  otherwise returns a negative number on error.
 */
hash_table *
hash_create(HASHCMP * cmp_func, int hash_sz, HASHHASH * hash_func)
{
    hash_table *hid = (hash_table*)malloc(sizeof(hash_table));
    if (!hash_sz)
        hid->size = (unsigned int) DEFAULT_HASH_SIZE;
    else
        hid->size = (unsigned int) hash_sz;
    /* allocate and null the buckets */
    hid->buckets = (hash_link**)malloc(hid->size * sizeof(hash_link *));
    hid->cmp = cmp_func;
    hid->hash = hash_func;
    hid->next = NULL;
    hid->current_slot = 0;
    return hid;
}

/*
 *  hash_join - joins a hash_link under its key lnk->key
 *  into the hash table 'hid'.  
 *
 *  It does not copy any data into the hash table, only links pointers.
 */
void
hash_join(hash_table * hid, hash_link * lnk)
{
    int i;
    i = hid->hash(lnk->key, hid->size);
    lnk->next = hid->buckets[i];
    hid->buckets[i] = lnk;
    hid->count++;
}

/*
 *  hash_lookup - locates the item under the key 'k' in the hash table
 *  'hid'.  Returns a pointer to the hash bucket on success; otherwise
 *  returns NULL.
 */
hash_link *
hash_lookup(hash_table * hid, const void *k)
{
    hash_link *walker;
    int b;
    assert(k != NULL);
    b = hid->hash(k, hid->size);
    for (walker = hid->buckets[b]; walker != NULL; walker = walker->next) {
	if ((hid->cmp) (k, walker->key) == 0) {
	    return (walker);
	}
	assert(walker != walker->next);
    }
    return NULL;
}

static void
hash_next_bucket(hash_table * hid)
{
    while (hid->next == NULL && ++hid->current_slot < hid->size)
	hid->next = hid->buckets[hid->current_slot];
}

/*
 *  hash_first - initializes the hash table for the hash_next()
 *  function.
 */
void
hash_first(hash_table * hid)
{
    assert(NULL == hid->next);
    hid->current_slot = 0;
    hid->next = hid->buckets[hid->current_slot];
    if (NULL == hid->next)
	hash_next_bucket(hid);
}

/*
 *  hash_next - returns the next item in the hash table 'hid'.
 *  Otherwise, returns NULL on error or end of list.  
 *
 *  MUST call hash_first() before hash_next().
 */
hash_link *
hash_next(hash_table * hid)
{
    hash_link* node = hid->next;
    if (NULL == node)
	return NULL;
    hid->next = node->next;
    if (NULL == hid->next)
	hash_next_bucket(hid);
    return node;
}

/*
 *  hash_last - resets hash traversal state to NULL
 *
 */
void
hash_last(hash_table * hid)
{
    assert(hid != NULL);
    hid->next = NULL;
    hid->current_slot = 0;
}

/*
 *  hash_remove_link - deletes the given hash_link node from the 
 *  hash table 'hid'.  Does not free the item, only removes it
 *  from the list.
 *
 *  An assertion is triggered if the hash_link is not found in the
 *  list.
 */
void
hash_remove_link(hash_table * hid, hash_link * hl)
{
    hash_link **P;
    int i;
    assert(hl != NULL);
    i = hid->hash(hl->key, hid->size);
    for (P = &hid->buckets[i]; *P; P = &(*P)->next) {
	if (*P != hl)
	    continue;
	*P = hl->next;
	if (hid->next == hl) {
	    hid->next = hl->next;
	    if (NULL == hid->next)
		hash_next_bucket(hid);
	}
	hid->count--;
	return;
    }
    assert(0);
}

/*
 *  hash_get_bucket - returns the head item of the bucket 
 *  in the hash table 'hid'. Otherwise, returns NULL on error.
 */
hash_link *
hash_get_bucket(hash_table * hid, unsigned int bucket)
{
    if (bucket >= hid->size)
	return NULL;
    return (hid->buckets[bucket]);
}

void
hashFreeItems(hash_table * hid, HASHFREE * free_func)
{
    hash_link *l;
    hash_link **list;
    int i = 0;
    int j;
    list = (hash_link**)malloc(hid->count * sizeof(hash_link *));
    hash_first(hid);
    while ((l = hash_next(hid)) && i < hid->count) {
	*(list + i) = l;
	i++;
    }
    for (j = 0; j < i; j++)
	free_func(*(list + j));
    free(list);
}

void
hashFreeMemory(hash_table * hid)
{
    if(hid == NULL)
        return;
    if (hid->buckets)
	free(hid->buckets);
    free(hid);
}

static int hash_primes[] =
{
    103,
    229,
    467,
    977,
    1979,
    4019,
    6037,
    7951,
    12149,
    16231,
    33493,
    65357
};

int
hashPrime(int n)
{
    int I = sizeof(hash_primes) / sizeof(int);
    int i;
    int best_prime = hash_primes[0];
    double min = fabs(log((double) n) - log((double) hash_primes[0]));
    double d;
    for (i = 0; i < I; i++) {
	d = fabs(log((double) n) - log((double) hash_primes[i]));
	if (d > min)
	    continue;
	min = d;
	best_prime = hash_primes[i];
    }
    return best_prime;
}

/*
 * return the key of a hash_link as a const string
 */
const char *
hashKeyStr(hash_link * hl)
{
    return (const char *) hl->key;
}

uint64_t getCurMillseconds() {
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * 1000 + now.tv_usec / 1000;
}

class Answer
{
public:
    Answer(int size)
    {
        if ((hid_ = hash_create((HASHCMP *) strcmp, size, hash4)) < 0) 
        {
            printf("hash_create error.\n");
            exit(1);
        }
        fd_ = open("tmp.dat", O_CREAT | O_RDWR, S_IRWXU | S_IRWXO);
        if (fd_ <= 0)
        {
            printf("open tmp.dat failed!\n");
            exit(1);
        }
        buf1_ = (char*)malloc(1024 * 1024);
        buf2_ = (char*)malloc(1024 * 1024);
        int len;
        while (read(fd_, &len, 4) > 0)
        {
            if (read(fd_, buf1_, len) != len)
            {
                printf("read key failed!\n");
                break;
            }
            if (read(fd_, &len, 4) != 4)
            {
                printf("read value len failed!\n");
                break;
            }
            buf1_[len] = 0;
            if (read(fd_, buf2_, len) != len)
            {
                printf("read value failed!\n");
                break;
            }
            buf2_[len] = 0;
            put(buf1_, buf2_, false);
        }
    }
    
    ~Answer()
    {
        if (buf1_)free(buf1_);
        if (buf2_)free(buf2_);
    }

    string get(string key)
    {
        hash_link* item = hash_lookup(hid_, key.c_str());
        if (item)
        {
            return (char*)item->val;
        }
        else
        {
            return "NULL";
        }
    }

    void put(string key, string value)
    {
        return put(key, value, true);
    }

    void put(string key, string value, bool write_flag)
    {
        //printf("put key:%s val:%s\n", key.c_str(), value.c_str());
        char* k = (char*)malloc(key.size() + 1);
        sprintf(k, "%s", key.c_str());
        
        char* v = (char*)malloc(value.size() + 1);
        sprintf(v, "%s", value.c_str());

        hash_link* item = (hash_link*)malloc(sizeof(hash_link));
        item->key = k;
        item->val = v;
        hash_join(hid_, item);

        if (write_flag)
        {
            int total_len = 0;
            int len = key.size();
            char* p = buf1_;
            memcpy(p, &len, 4);
            p += 4;
            memcpy(p, k, len);
            p += len;
            len = value.size();
            memcpy(p, &len, 4);
            p+= 4;
            memcpy(p, v, len);
            p+= len;

            write(fd_, buf1_, p - buf1_);

        }

    }

private:
    hash_table* hid_;
    int fd_;
    char* buf1_;
    char* buf2_;
};

int main(int argc, char** argv)
{
    Answer answer(1000000);

    {
        char query[16];
        sprintf(query, "%015d", 8);
        string val = answer.get(query);
        printf("query key:%s val:%s\n", query, val.c_str());

        return 0;

    }


    if (argc != 2)
    {
        printf("usage:%s count\n", argv[0]);
        return 1;
    }

    
    uint64_t begin = getCurMillseconds();
    int count = atoi(argv[1]);
    for (int i= 0; i < count; ++i)
    {
        char key[16];
        char val[16];
        sprintf(key, "%015d", i);
        sprintf(val, "%015d", i);
        answer.put(key, val);
        printf("add key:%s val:%s\n", key, val);
    }
    uint64_t end = getCurMillseconds();
    printf("add %d items costs %lu ms\n", count, end - begin);

    char query[16];
    sprintf(query, "%015d", 1);
    string val = answer.get(query);
    printf("query key:%s val:%s\n", query, val.c_str());

    begin = getCurMillseconds();
    for (int i = 0; i < count; ++i)
    {
        char query[16];
        sprintf(query, "%015d", i);
        string val = answer.get(query);
        printf("query key:%s val:%s\n", query, val.c_str());
    }
    end = getCurMillseconds();
    printf("query %d items costs %lu ms\n", count, end - begin);
    sleep(60);
    return 0; 
}

