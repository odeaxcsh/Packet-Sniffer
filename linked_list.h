#ifndef __LINKED_LIST
#define __LINKED_LIST

#include <stdlib.h>

struct Linked_list_node
{
	struct Linked_list_node *next;
	struct Linked_list_node *prev;
	void *object;
};

struct Linked_list
{
	struct Linked_list_node *head;
	struct Linked_list_node *tail;
};

void free_linked_list(struct Linked_list_node *head)
{
	if(head == NULL)
		return;

	struct Linked_list_node *current = head->next;
	while(current != NULL) {
		struct Linked_list_node *next = current->next;
		free(current);
		current = next;
	}

	current = head;
	while(current != NULL) {
		struct Linked_list_node *prev = current->prev;
		free(current);
		current = prev;
	}
}

struct Linked_list *create_linke_list()
{
	struct Linked_list *list = (struct Linked_list*)malloc(sizeof(struct Linked_list));
	list->head = (struct Linked_list_node*)malloc(sizeof(struct Linked_list_node));
	list->tail = (struct Linked_list_node*)malloc(sizeof(struct Linked_list_node));
	list->head->object = list->tail->object = NULL;
	list->tail->next = list->head->prev = NULL;
	list->tail->prev = list->head;
	list->head->next = list->tail;
	return list;
}

void Linked_list_push_front(struct Linked_list *list, void *object)
{
	struct Linked_list_node *new_node = (struct Linked_list_node *)malloc(sizeof(struct Linked_list_node));
	new_node->next = list->head->next;
	new_node->prev = list->head;
	new_node->object = object;
	list->head->next = new_node;
	new_node->next->prev = new_node;
}

struct Linked_list_node *Linked_list_cut(struct Linked_list *list)
{
	if(list->head->next == list->tail) {
		return NULL;
	} else {
		struct Linked_list_node *cutted_list = list->head->next;
		list->tail->prev->next = NULL;
		list->head->next->prev = NULL;
		list->tail->prev = list->head;
		list->head->next = list->tail;
		return cutted_list;
	}
}

#endif 