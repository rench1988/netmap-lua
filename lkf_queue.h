/**
 * @author [rench]
 * @create date 2017-11-22 03:23:54
 * @modify date 2017-11-22 03:23:54
 * @desc []
*/
#ifndef __lkf_queue_h_
#define __lkf_queue_h_


typedef struct lkf_queue_s lkf_queue_t;
typedef struct lkf_node_s  lkf_node_t;
typedef struct lkf_ring_s  lkf_ring_t;

struct lkf_node_s {
	void       *data;
	lkf_node_t *next;
};

struct lkf_queue_s {
	lkf_node_t *head;
	lkf_node_t *tail;
	lkf_node_t *dummy;	
};

struct lkf_ring_s {
	void       **datas;
	int    		 head;
	int    		 tail;
	unsigned int size;
};



lkf_queue_t *lkf_queue_init(void);
void        *lkf_queue_pop(lkf_queue_t *queue);
int          lkf_queue_push(lkf_queue_t *queue, void *data);

lkf_ring_t *lkf_ring_init(unsigned int size);
int         lkf_ring_push(lkf_ring_t *ring, void *data);
void       *lkf_ring_pop(lkf_ring_t *ring);
void        lkf_ring_free(lkf_ring_t *ring);

#endif