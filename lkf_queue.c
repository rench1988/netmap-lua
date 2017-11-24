/**
 * @author [rench]
 * @create date 2017-11-22 03:23:54
 * @modify date 2017-11-22 03:23:54
 * @desc []
*/
#include <stdlib.h>
#include <string.h>

#include "lkf_queue.h"

#define lkf_ring_incre(x, rlen) ((x + 1) & (rlen - 1))
#define lkf_ring_empty(s, e) (s == e)
#define lkf_ring_full(s, e, rlen) (lkf_ring_incre(s, rlen) == e)

static unsigned int clp2(unsigned int x);

static unsigned int clp2(unsigned int x) 
{
	   x = x - 1;
	   x = x | (x >> 1);
	   x = x | (x >> 2);
	   x = x | (x >> 4);
	   x = x | (x >> 8);
	   x = x | (x >> 16);
	   return x + 1;
}

int lkf_queue_push(lkf_queue_t *queue, void *data)
{
	lkf_node_t *node = (lkf_node_t *)malloc(sizeof(lkf_node_t));
	if (node == NULL) {
		return -1;
	}

	node->data = data;
	node->next = NULL;

	queue->tail->next = node;
	queue->tail = node;

	return 0;
}

void *lkf_queue_pop(lkf_queue_t *queue)
{
	void       *res;
	lkf_node_t *head;

	head = queue->head;

	if (head->next == NULL) {
		return NULL;
	}

	res = head->next->data;
	queue->head = head->next;

	free(head);

	return res;
}

lkf_queue_t *lkf_queue_init(void)
{
    lkf_queue_t *lkfq = (lkf_queue_t *)malloc(sizeof(lkf_queue_t));
    if (lkfq == NULL) {
    	goto failed;
    }

    lkfq->dummy = (lkf_node_t *)malloc(sizeof(lkf_node_t));
    if (lkfq->dummy == NULL) {
    	goto failed;
    }

    lkfq->dummy->data = NULL;
    lkfq->dummy->next = NULL;

    lkfq->head = lkfq->dummy;
    lkfq->tail = lkfq->dummy;

    return lkfq;

failed:
	if (lkfq && lkfq->dummy) free(lkfq->dummy);
	if (lkfq) free(lkfq);

	return NULL;
}

lkf_ring_t *lkf_ring_init(unsigned int size)
{
	size = clp2(size);

	lkf_ring_t *ring = (lkf_ring_t *)malloc(sizeof(lkf_ring_t));
	if (ring == NULL) {
		goto failed;
	}

	ring->datas = (void **)malloc(sizeof(void *) * size);
	if (ring->datas == NULL) {
		goto failed;
	}

	ring->head = 0;
	ring->tail = 0;
    ring->size = size;

	return ring;

failed:
	if (ring && ring->datas) free(ring->datas);
	if (ring) free(ring);

	return NULL;
}

int lkf_ring_push(lkf_ring_t *ring, void *data)
{
	if (lkf_ring_full(ring->tail, ring->head, ring->size)) {
		return -1;
	}

	int next_tail = lkf_ring_incre(ring->tail, ring->size);

	ring->datas[ring->tail] = data;
    ring->tail = next_tail;
    

	return 0;
}

void *lkf_ring_pop(lkf_ring_t *ring)
{
	if (lkf_ring_empty(ring->head, ring->tail)) {
		return NULL;
	}

	void *data = ring->datas[ring->head];

    ring->head = lkf_ring_incre(ring->head, ring->size);

	return data;
}

void lkf_ring_free(lkf_ring_t *ring)
{
	if (ring && ring->datas) free(ring->datas);
	if (ring) free(ring);

	return;
}
