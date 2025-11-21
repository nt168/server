#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>
#include "common.h"
#include "shmlst.h"



shmlst* create_list();
shmlst* insert_list();

shmlst* create_list()
{
    int shm_fd;
    size_t shm_size;
    void* shm_base;
    shmlst* header;
    node* nodes;
    sem_t* mutex;

    if (shm_unlink(SHM_NAME) == -1) {
    	perror("shm_unlink");
    }

    if (sem_unlink(SEM_NAME) == -1) {
		perror("sem_unlink");
	}

    shm_size = sizeof(shmlst) + INITIAL_CAPACITY * sizeof(node);

    shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT | O_EXCL, 0666);
    if(shm_fd < 0) {
        perror("shm_open");
        return NULL;
    }

    if(ftruncate(shm_fd, shm_size) == -1) {
        perror("ftruncate");
        close(shm_fd);
        return NULL;
    }

    shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    memset(shm_base, 0, shm_size);
    if(shm_base == MAP_FAILED) {
        perror("mmap");
        close(shm_fd);
        return NULL;
    }

    close(shm_fd);

    header = (shmlst*)shm_base;
    header->num = INITIAL_CAPACITY;
    header->used = 0;
    header->entr = NULL;
    header->tail = NULL;
    header->curr = NULL;
    header->pos = NULL;
    header->scal = shm_size;
    nodes = (node*)((char*)shm_base + sizeof(shmlst));
    for(int i = 0; i < INITIAL_CAPACITY; i++) {
        nodes[i].next = (i < INITIAL_CAPACITY - 1) ? (struct ddl*)(&nodes[i+1]) : NULL;
        nodes[i].prev = (i > 0) ? (struct ddl*)(&nodes[i-1]) : NULL;
    }

    header->entr = &nodes[0];
    header->tail = &nodes[INITIAL_CAPACITY - 1];

    header->curr = header->entr;
    mutex = sem_open(SEM_NAME, O_CREAT, 0666, 1);
	if(mutex == SEM_FAILED){
		perror("sem_open");
		return NULL;
	}
	sem_close(mutex);
    return header;
}

int expend_list(shmlst** lst)
{
    int fd;
    size_t shm_size, new_shm_size;
    void* shm_base;
    shmlst* header;
    node* nodes;
    shmlst* temp_header;

//temp_header
    shm_size = (*lst)->scal;
	temp_header = malloc(shm_size);
	memset(temp_header, 0, shm_size);
	if(temp_header == NULL) {
		perror("malloc");
		return 1;
	}

	size_t old_num = (*lst)->num;
	memcpy(temp_header, *lst, shm_size);
	memset(*lst, 0, (*lst)->scal);
	shm_unlink(SHM_NAME);
	munmap(*lst, shm_size);

    size_t new_num = old_num + CAPACITY_INCREMENT;
    new_shm_size = sizeof(shmlst) + new_num * sizeof(node);

    fd = shm_open(SHM_NAME, O_RDWR | O_CREAT | O_EXCL, 0666);
    if(fd < 0) {
        perror("shm_open");
        free(temp_header);
        return 1;
    }

    if(ftruncate(fd, new_shm_size) == -1) {
        perror("ftruncate");
        close(fd);
        free(temp_header);
        return 1;
    }

    shm_base = mmap(NULL, new_shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(shm_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        free(temp_header);
        return 1;
    }
    close(fd);

    header = (shmlst*)shm_base;
    nodes = (node*)((char*)shm_base + sizeof(shmlst));

    memcpy(header, temp_header, sizeof(shmlst));
    header->num = new_num;

    memcpy(nodes, (char*)temp_header + sizeof(shmlst), old_num * sizeof(node));

    for(size_t i = old_num; i < new_num; i++) {
        memset(&nodes[i].data, 0, sizeof(rgdt));
        nodes[i].next = (i < new_num - 1) ? (struct ddl*)(&nodes[i+1]) : NULL;
        nodes[i].prev = (i > 0) ? (struct ddl*)(&nodes[i-1]) : NULL;
    }

    for(size_t i = 0; i < old_num; i++) {
        if(nodes[i].next != NULL && i + 1 < new_num) {
            nodes[i].next = (struct ddl*)(&nodes[i+1]);
        }
        if(nodes[i].prev != NULL && i > 0) {
            nodes[i].prev = (struct ddl*)(&nodes[i-1]);
        }
    }

    header->tail = &nodes[header->used - 1];
    header->curr = &nodes[header->used - 1];
    header->scal = new_shm_size;
    header->entr = nodes;
    free(temp_header);
    *lst = header;
    return 0;
}

shmlst* insert_list(rgdt data)
{
    int fd;
    size_t shm_size;
    void* shm_base;
    shmlst* header;
    node* nodes;
    sem_t* mutex;

    mutex = sem_open(SEM_NAME, 0);
    if(mutex == SEM_FAILED){
		perror("sem_open");
		return NULL;
    }

    if(sem_wait(mutex) == -1) {
        perror("sem_post");
        return NULL;
    }

    fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if(fd < 0) {
        perror("shm_open");
        return NULL;
    }

    struct stat sb;
    if(fstat(fd, &sb) == -1) {
        perror("fstat");
        close(fd);
        return NULL;
    }

    shm_size = sb.st_size;

    shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(shm_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return NULL;
    }

    close(fd);

    header = (shmlst*)shm_base;
    nodes = (node*)((char*)shm_base + sizeof(shmlst));

    for(int i = 0; i < header->num; i++) {
        nodes[i].next = (i < header->num - 1) ? (struct ddl*)(&nodes[i+1]) : NULL;
        nodes[i].prev = (i > 0) ? (struct ddl*)(&nodes[i-1]) : NULL;
    }

    header->entr = &nodes[0];
    if(header->used == 0){
    	header->tail = NULL;
    	header->curr = NULL;
    }else{
    	header->tail = &nodes[header->used - 1];
    	header->curr = &nodes[header->used - 1];
    }

    if(header->used == header->num) {
//扩容
    	fprintf(stderr, "列表已满，扩容.\n");
        if(expend_list(&header) != 0){
        	sem_post(&header->mutex);
			munmap(shm_base, shm_size);
			return NULL;
        }
        nodes = header->entr;
    }
    node* new_node = &nodes[header->used];
    memcpy(&(new_node->data), &data, sizeof(rgdt));
    new_node->next = NULL;
    new_node->prev = NULL;

    if(header->used == 0) {
        header->entr = new_node;
        header->tail = new_node;
    } else {
        node* tail = header->tail;
        tail->next = (struct ddl*)(new_node);
        new_node->prev = (struct ddl*)(tail);
        header->tail = new_node;
    }

    header->used += 1;

    if(header->used < header->num) {
        header->curr = &nodes[header->used];
    } else {
        header->curr = NULL;
    }

    if(sem_post(mutex) == -1) {
        perror("sem_post");
        return NULL;
    }
    sem_close(mutex);
    return header;
}

int print_list()
{
    int fd;
    size_t shm_size;
    void* shm_base;
    shmlst* header;
    node* nodes;
    sem_t* mutex;

    mutex = sem_open(SEM_NAME, 0);
    if(mutex == SEM_FAILED){
		perror("sem_open");
		return -1;
    }

    if(sem_wait(mutex) == -1) {
        perror("sem_wait");
        return -1;
    }

    fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if(fd < 0) {
        perror("shm_open");
        return -1;
    }

    struct stat sb;
    if(fstat(fd, &sb) == -1) {
        perror("fstat");
        close(fd);
        return -1;
    }

    shm_size = sb.st_size;

    shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(shm_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return -1;
    }

    close(fd);

    header = (shmlst*)shm_base;
    nodes = (node*)((char*)shm_base + sizeof(shmlst));
    for(int i = 0; i < header->num; i++) {
        nodes[i].next = (i < header->num - 1) ? (struct ddl*)(&nodes[i+1]) : NULL;
        nodes[i].prev = (i > 0) ? (struct ddl*)(&nodes[i-1]) : NULL;
    }

    header->entr = &nodes[0];
    header->tail = &nodes[header->num - 1];

    header->curr = header->entr;

    node* current = header->entr;
    for(int i =0; i < header->used; i++){
    	printf("Address: %s, Port: %d, Type: %d\n",current->data.add, current->data.port, current->data.ttp);
    	current = (node*)(current->next);
    }

    if(sem_post(mutex) == -1) {
        perror("sem_post");
        return -1;
    }
    sem_close(mutex);

    return 0;
}

bool create_shm(const char* shm_nam, const char* sem_nam, size_t len)
{
    int shm_fd;
    size_t shm_size;
    shmst* hder = NULL;
    void* shm_base;
    sem_t* mutex;

    if (shm_unlink(shm_nam) == -1) {
    	perror("shm_unlink");
    }

    if (sem_unlink(SEM_NAME) == -1) {
		perror("sem_unlink");
	}

    shm_size = len + sizeof(shmst);

    shm_fd = shm_open(shm_nam, O_RDWR | O_CREAT | O_EXCL, 0666);
    if(shm_fd < 0) {
        perror("shm_open");
        return false;
    }

    if(ftruncate(shm_fd, shm_size) == -1) {
        perror("ftruncate");
        close(shm_fd);
        return false;
    }

    shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    memset(shm_base, 0, shm_size);
    if(shm_base == MAP_FAILED) {
        perror("mmap");
        close(shm_fd);
        return false;
    }

    close(shm_fd);

    hder = (shmst*)shm_base;
    hder->len = shm_size;

    mutex = sem_open(sem_nam, O_CREAT, 0666, 1);
	if(mutex == SEM_FAILED){
		perror("sem_open");
		return false;
	}
	sem_close(mutex);
    return true;
}

bool shm_write(const char* shm_nam, const char* sem_nam, void* data, size_t len)
{
	int fd;
	size_t shm_size;
	void* shm_base;
	shmst* hder;
	sem_t* mutex;

	mutex = sem_open(sem_nam, 0);
	if(mutex == SEM_FAILED){
		perror("sem_open");
		return false;
	}

	if(sem_wait(mutex) == -1) {
		perror("sem_post");
		return false;
	}

	fd = shm_open(shm_nam, O_RDWR, 0666);
	if(fd < 0) {
		perror("shm_open");
		return false;
	}

	struct stat sb;
	if(fstat(fd, &sb) == -1) {
		perror("fstat");
		close(fd);
		return false;
	}

	shm_size = sb.st_size;

	shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(shm_base == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return false;
	}
	close(fd);

	hder = (shmst*)shm_base;
	if(len > hder->len){
		return false;
	}

	memset(hder->dat, 0, hder->len);
	memcpy(hder->dat, data, len);
	hder->len = len;

	if(sem_post(mutex) == -1) {
		perror("sem_post");
		return false;
	}
	sem_close(mutex);
	return true;
}

bool shm_read(const char* shm_nam, const char* sem_nam, void** dat, size_t* len)
{
    int fd;
    size_t shm_size;
    void* shm_base;
    shmst* hder;
    sem_t* mutex;

    mutex = sem_open(sem_nam, 0);
    if(mutex == SEM_FAILED){
		perror("sem_open");
		return false;
    }

    if(sem_wait(mutex) == -1) {
        perror("sem_wait");
        return false;
    }

    fd = shm_open(shm_nam, O_RDWR, 0666);
    if(fd < 0) {
        perror("shm_open");
        return false;
    }

    struct stat sb;
    if(fstat(fd, &sb) == -1) {
        perror("fstat");
        close(fd);
        return false;
    }

    shm_size = sb.st_size;

    shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(shm_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return false;
    }

    close(fd);

    hder = (shmst*)shm_base;
    *dat = (void*)malloc(hder->len);
    memset(*dat, 0, hder->len);
    memcpy(*dat, hder->dat, hder->len);
    *len = hder->len;

    if(sem_post(mutex) == -1) {
        perror("sem_post");
        return false;
    }
    sem_close(mutex);
    return true;
}

void shm_free(const char* shm_nam, const char* sem_nam)
{
	shm_unlink(shm_nam);
	sem_unlink(sem_nam);
}

