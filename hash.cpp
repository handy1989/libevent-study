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
#include <map>
#include <vector>

using std::string;
using std::map;
using std::vector;

typedef void HASHFREE(void *);
typedef int HASHCMP(const void *, const void *);
typedef unsigned int HASHHASH(const void *, unsigned int);

struct hash_link {
    void *key;
    void* val;
    hash_link *next;
};

struct hash_table {
    hash_link **buckets;
    HASHCMP *cmp;
    HASHHASH *hash;
    unsigned int size;
    unsigned int current_slot;
    hash_link *next;
    int count;
};

#define  DEFAULT_HASH_SIZE 7951	/* prime number < 8192 */

static void hash_next_bucket(hash_table * hid);

unsigned int hash4(const void *data, unsigned int size)
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

hash_table* hash_create(HASHCMP * cmp_func, int hash_sz, HASHHASH * hash_func)
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

void hash_join(hash_table * hid, hash_link * lnk)
{
    int i;
    i = hid->hash(lnk->key, hid->size);
    lnk->next = hid->buckets[i];
    hid->buckets[i] = lnk;
    hid->count++;
}

hash_link* hash_lookup(hash_table * hid, const void *k)
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

void hash_first(hash_table * hid)
{
    assert(NULL == hid->next);
    hid->current_slot = 0;
    hid->next = hid->buckets[hid->current_slot];
    if (NULL == hid->next)
	hash_next_bucket(hid);
}

hash_link* hash_next(hash_table * hid)
{
    hash_link* node = hid->next;
    if (NULL == node)
	return NULL;
    hid->next = node->next;
    if (NULL == hid->next)
	hash_next_bucket(hid);
    return node;
}

hash_link* hash_get_bucket(hash_table * hid, unsigned int bucket)
{
    if (bucket >= hid->size)
	return NULL;
    return (hid->buckets[bucket]);
}

void hashFreeItems(hash_table * hid, HASHFREE * free_func)
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

void hashFreeMemory(hash_table * hid)
{
    if(hid == NULL)
        return;
    if (hid->buckets)
	free(hid->buckets);
    free(hid);
}

uint64_t getCurMillseconds() {
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * 1000 + now.tv_usec / 1000;
}

struct hash_value
{
    void* value_raw;
    int value_offset;
    int value_len;
};

class Answer
{
public:
    Answer()
    {
        if ((hid_ = hash_create((HASHCMP *) strcmp, 1000000, hash4)) < 0) 
        {
            exit(1);
        }
        fd_data_ = open("data.db", O_CREAT | O_RDWR, S_IRWXU | S_IRWXO);
        if (fd_data_ <= 0)
        {
            exit(1);
        }
        fd_index_ = open("index.db", O_CREAT | O_RDWR, S_IRWXU | S_IRWXO);
        if (fd_index_ <= 0)
        {
            exit(1);
        }

        buf1_ = (char*)malloc(1024 * 1024);
        buf2_ = (char*)malloc(1024 * 1024);

        total_value_size_in_memory_ = 0;
        total_value_offset_ = 0;
        max_value_size_in_memory_ = 10 * 1024 * 1024;
        last_value_offset_ = 0;
        last_value_len_ = 0;

        read_index();
        read_data();
    }
    
    ~Answer()
    {
        if (buf1_)free(buf1_);
        if (buf2_)free(buf2_);
    }


    void read_index()
    {
        string key;
        int value_offset;
        int value_len;
        int offset = 0;
        while (true)
        {
            if (!read_index_from_disk(key, value_offset, value_len))
            {
                break;
            }
            offset += (4 + key.size() + 4 + 4);

            char* k = (char*)malloc(key.size() + 1);
            memcpy(k, key.c_str(), key.size());
            k[key.size()] = 0; 

            hash_link* item = hash_lookup(hid_, key.c_str());
            if (item)
            {
                hash_value* value = (hash_value*)item->val;
                value->value_offset = value_offset;
                value->value_len = value_len;
            }
            else
            {
                hash_value* v = (hash_value*)malloc(sizeof(hash_value));
                v->value_raw = NULL;
                v->value_offset = value_offset;
                v->value_len = value_len;
                item = (hash_link*)malloc(sizeof(hash_link));
                item->key = k;
                item->val = v;
                hash_join(hid_, item);
            }
        }
        lseek(fd_index_, offset, SEEK_SET); 
    }
    
    bool read_index_from_disk(string& key, int& value_offset, int& value_len)
    {
        // keylen key vlen value_offset
        int klen;
        if (read(fd_index_, &klen, 4) != 4)
        {
            return false;
        }
        if (read(fd_index_, buf1_, klen) != klen)
        {
            return false;
        }
        if (read(fd_index_, &value_len, 4) != 4)
        {
            return false;
        }
        if (read(fd_index_, &value_offset, 4) != 4)
        {
            return false;
        }
        buf1_[klen] = 0;
        key = buf1_;
        last_value_offset_ += value_len;
        last_value_len_ = value_len;
        return true;
    }

    void read_data()
    {
       // 遍历hash表，读取value_offset，再从磁盘读取真实的value
       hash_first(hid_);
       hash_link* node;
       int count = 0;
       while ((node = hash_next(hid_)) && count < hid_->count)
       {
            char* key = (char*)node->key;
            hash_value* value = (hash_value*)node->val;
            if (total_value_size_in_memory_ < max_value_size_in_memory_)
            {
                char* v;
                if (read_data_from_disk(value->value_offset, value->value_len, &v))
                {
                    // 读取value成功
                    hash_link* item = hash_lookup(hid_, key);
                    if (item)
                    {
                        ((hash_value*)item->val)->value_raw = v;
                    }
                }
                else
                {
                    value->value_offset = -1;
                }
            }
            ++count;
       }
       // 读取最后一块value，看是否完好
       lseek(fd_data_, last_value_offset_, SEEK_SET);
       if (read(fd_data_, buf1_, last_value_len_) != last_value_len_)
       {
           lseek(fd_data_, last_value_offset_, SEEK_SET);
           total_value_offset_ = last_value_offset_;
       }
       else
       {
           total_value_offset_ = last_value_offset_ + last_value_len_;
       }
    }

    bool read_data_from_disk(const int offset, const int value_len, char** value)
    {
        lseek(fd_data_, offset, SEEK_SET);
        if (read(fd_data_, buf1_, value_len) != value_len)
        {
            return false;
        }
        *value = (char*)malloc(value_len + 1);
        memcpy(*value, buf1_, value_len);
        (*value)[value_len] = 0;

        total_value_size_in_memory_ += value_len;

        return true;
    }

    string get(string key)
    {
        hash_link* item = hash_lookup(hid_, key.c_str());
        if (item)
        {
            hash_value* hval = (hash_value*)item->val;
            if (hval->value_raw)
            {
                return (char*)hval->value_raw;
            }
            else if (hval->value_offset > 0)
            {
                lseek(fd_data_, hval->value_offset, SEEK_SET);
                read(fd_data_, buf1_, hval->value_len);
                buf1_[hval->value_len] = 0;
                return buf1_;
            }
            else
            {
                return "NULL";
            }
        }
        else
        {
            return "NULL";
        }
    }

    void put(const string& key, const string& value)
    {
        int static total_size = 0;
        int static total_key_size = 0;
        total_size += value.size();
        // 追加索引文件
        int klen = key.size();
        write(fd_index_, &klen, 4);
        write(fd_index_, key.c_str(), klen);
        int vlen = value.size();
        write(fd_index_, &vlen, 4);
        write(fd_index_, &total_value_offset_, 4);

        // 追加数据文件
        lseek(fd_data_, total_value_offset_, SEEK_SET);
        write(fd_data_, value.c_str(), value.size());
        last_value_offset_ = total_value_offset_;
        last_value_len_ = value.size();
        total_value_offset_ += value.size();

        // 添加到hash表
        hash_link* item = hash_lookup(hid_, key.c_str());
        if (item)
        {
            hash_value* v = (hash_value*)item->val;
            if (v->value_raw)
            {
                free(v->value_raw);
                v->value_raw = NULL;
                total_value_size_in_memory_ -= v->value_len;
                //printf("free memory size:%d total_value_size_in_memory_:%d total_size:%d\n", v->value_len, total_value_size_in_memory_, total_size);
            }

            v->value_len = value.size();
            v->value_offset = last_value_offset_;
            if (total_value_size_in_memory_ + value.size() < max_value_size_in_memory_)
            {
                char* new_value_raw = (char*)malloc(value.size() + 1);
                memcpy(new_value_raw, value.c_str(), value.size());
                new_value_raw[value.size()] = 0;
                v->value_raw = new_value_raw;
                total_value_size_in_memory_ += value.size();

                //printf("replace value, malloc memory size:%ld total_value_size_in_memory_:%d total_size:%d\n", value.size(), total_value_size_in_memory_, total_size);
            }
        }
        else
        {
            char* k = (char*)malloc(key.size() + 1);
            memcpy(k, key.c_str(), key.size());
            k[key.size()] = 0;

            item = (hash_link*)malloc(sizeof(hash_link));
            item->key = k;

            total_key_size += (key.size() + sizeof(hash_link));
            //printf("malloc key, total_key_size:%d total_value_size:%d\n", total_key_size, total_size);

            hash_value* hval = (hash_value*)malloc(sizeof(hash_value));
            hval->value_len = value.size();
            hval->value_offset = last_value_offset_;
            if (total_value_size_in_memory_ + value.size() < max_value_size_in_memory_)
            {
                char* v = (char*)malloc(value.size() + 1);
                memcpy(v, value.c_str(), value.size());
                v[value.size()] = 0;
                hval->value_raw = v;
                total_value_size_in_memory_ += value.size();
                //printf("new value, malloc memory size:%ld total_value_size_in_memory_:%d total_size:%d\n", value.size(), total_value_size_in_memory_, total_size);
            }
            else
            {
                hval->value_raw = NULL;
            }
            item->val = hval;
            hash_join(hid_, item);

        }
        static int count = 0;
        if (count++ % 10000 == 1)
        {
            ///printf("count:%d add klen:%ld vlen:%ld total_value_size_in_memory_:%d\n", count, key.size(), value.size(), total_value_size_in_memory_);
        }
    }

    void stat_hash()
    {
        hash_first(hid_);
        hash_link* node;
        int count = 0;
        while ((node = hash_next(hid_)) && count < hid_->count)
        {
            hash_value* hval = (hash_value*)node->val;
            //printf("key:%s\nvalue_offset:%d value_len:%d value:%s\n", (char*)node->key, hval->value_offset, hval->value_len, (char*)hval->value_raw);
            ++count;
        }
        printf("total count:%d\n", count);
    }

private:
    hash_table* hid_;
    int fd_data_;
    int fd_index_;
    char* buf1_;
    char* buf2_;
    int total_value_size_in_memory_;
    int total_value_offset_;
    int max_value_size_in_memory_;
    int last_value_offset_;
    int last_value_len_;
};

void random_buf(char* buf, int len)
{
    for (int i = 0; i < len; ++i)
    {
        buf[i] = rand() % 10 + '0';
    }
    buf[len] = 0;
}

void test1(int count)
{
    Answer answer;
    uint64_t begin = getCurMillseconds();
    char *key = (char*)malloc(1024 * 1024);
    char *val= (char*)malloc(1024 * 1024);
    int64_t total_len = 0;
    vector<string> keys;
    int key_len = rand() % 290 + 10;
    total_len += key_len;
    random_buf(key, key_len);
    for (int i = 0; i < count; ++i)
    {
        int val_len = rand() % 2048 + 1024;
        total_len += val_len;
        random_buf(val, val_len);
        //sprintf(key, "%08d", i);
        //sprintf(val, "%08d", i);
        answer.put(key, val);
        keys.push_back(key);
        //printf("add key:%s val:%s\n", key, val);
    }
    uint64_t end = getCurMillseconds();
    printf("put hash %d items costs %lu ms\n", count, end - begin);
    begin = end;
    for (vector<string>::iterator it = keys.begin(); it != keys.end(); ++it)
    {
        string val = answer.get(*it);
    }
    end = getCurMillseconds();
    printf("query hash %lu items costs %lu ms\n", keys.size(), end - begin);

    if (key) free(key);
    if (val) free(val);

    answer.stat_hash();
}

void test2(int count)
{
    Answer answer;
    uint64_t begin = getCurMillseconds();
    char *key = (char*)malloc(1024 * 1024);
    char *val = (char*)malloc(1024 * 1024);
    for (int i = 0; i < count; ++i)
    {
        sprintf(key, "%08d", i);
        sprintf(val, "%08d", i);
        answer.put(key, val);
        printf("add key:%s val:%s\n", key, val);
        printf("get key:%s val:%s\n", key, answer.get(key).c_str());
    }
    uint64_t end = getCurMillseconds();
    printf("add %d count item costs %lu ms\n", count, end - begin);
}

int main(int argc, char** argv)
{
    test1(50000);
    sleep(10);
    return 0;
    {
        //char query[16];
        //sprintf(query, "%015d", 8);
        //string val = answer.get(query);
        //printf("query key:%s val:%s\n", query, val.c_str());

        //return 0;

    }


    if (argc != 2)
    {
        printf("usage:%s count\n", argv[0]);
        return 1;
    }

    
    Answer answer;
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

