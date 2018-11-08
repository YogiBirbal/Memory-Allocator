/*
 * All functions you make for the assignment must be implemented in this file.
 * Do not submit your assignment with a main function in this file.
 * If you submit with a main function in this file, you will get a zero.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "debug.h"
#include "budmm.h"


/*
 * You should store the heads of your free lists in these variables.
 * Doing so will make it accessible via the extern statement in budmm.h
 * which will allow you to pass the address to sf_snapshot in a different file.
 */
extern bud_free_block free_list_heads[NUM_FREE_LIST];
void *find_next_free(bud_free_block *list);
void *bud_break_up(uint64_t bottom_block, bud_free_block *breakblock,uint32_t rsize);
uint64_t get_block_ord(bud_free_block block);
int valid_header(void *ptr);
void *coalesce_bud(bud_free_block *p, bud_free_block *bud);

void *bud_malloc(uint32_t rsize) {

    /* Validate rsize */
    if(rsize <= 0  || rsize > MAX_BLOCK_SIZE - sizeof(bud_header)){
        errno = EINVAL;
        return NULL;
    }
    int total = rsize + sizeof(bud_header);
    int i;
    void *nxt;
    int found = 0;
    void *nxtlst;
    char *ret;
    bud_free_block *temp;


    for(i = 0; i < NUM_FREE_LIST; i++){
        int cur = 1 << (i + ORDER_MIN); //Current Block Length of free_list_heads[i]

        while(cur >= total){    //Appropriate List
            if(//free_list_heads[i].next != &free_list_heads[0] &&

                (nxt = find_next_free(&free_list_heads[i])) != NULL){ //List != Empty, nxt is block we can use
                temp = (bud_free_block *) nxt;
                free_list_heads[i].next = free_list_heads[i].next -> next;
                temp -> header.allocated = 1;
                temp -> header.rsize = rsize;

                if(rsize + sizeof(bud_header) < ORDER_TO_BLOCK_SIZE(temp -> header.order) ){
                    temp -> header.padded = 1;
                }
                ret = (void *)temp;
                ret += sizeof(bud_header);
                return ret;



            }else{ // Need space from higher order lists, if none then bud_sbrk

                for(int j = i + 1; j < NUM_FREE_LIST; j++){
                    if((nxtlst = find_next_free(&free_list_heads[j])) != NULL ){ // nxtlst points to block that can be broken
                        //Break nxtlst up, put into appropriate lists

                        ret = bud_break_up(i + ORDER_MIN, nxtlst, rsize);
                        ret +=  sizeof(bud_header);

                        return ret;
                        found = 1;
                        break;
                    }
                }

                if(!found){ // Get space from bud_sbrk && break up

                    bud_free_block* b = (bud_free_block *)bud_sbrk();

                    if(b == (void*)-1){
                        errno = ENOMEM;
                        return NULL;

                    }

                    b -> header.order = ORDER_MAX - 1;
                    b -> header.allocated = 0;

                    b -> next = free_list_heads[ORDER_MAX  - 1 - ORDER_MIN].next;
                    b -> prev = free_list_heads[ORDER_MAX - 1 - ORDER_MIN].prev;
                    free_list_heads[ORDER_MAX - 1- ORDER_MIN].next = b;

                    ret = bud_break_up(i + ORDER_MIN, b, rsize);
                    //ret -> header.allocated = 0x1;
                    //printf("ALL%i\n", ret -> header.allocated);

                    ret +=  sizeof(bud_header);
                    return ret;
                }

            }
        }

    }



    return NULL;
}



/*
 * Breaks up a specified until specified size, puts into appropriate lists
 */
void *bud_break_up(uint64_t bottom_block, bud_free_block *breakblock, uint32_t rsize){

    while(get_block_ord(*breakblock) > bottom_block){
        int orig = get_block_ord(*breakblock);
        int nxtsize = ORDER_TO_BLOCK_SIZE(get_block_ord(*breakblock)) / 2;

        //Modify Second half
        bud_free_block *new = (bud_free_block *)((char *)breakblock + nxtsize);
        new -> header.order =  orig - 1;
        new -> header.allocated = 0;
        new -> next = free_list_heads[orig - 1 - ORDER_MIN].next;
        new -> prev = free_list_heads[orig - 1 - ORDER_MIN].prev;
        free_list_heads[orig - 1 - ORDER_MIN].next = new;
        //free_list_heads[orig - 1 - ORDER_MIN].prev

        //Modify First half
        breakblock -> header.order = orig - 1;
        //free_list_heads[orig - ORDER_MIN].next = free_list_heads[orig - ORDER_MIN].next -> next;
        int found = 0;

        bud_free_block *f = &free_list_heads[orig - ORDER_MIN];
        while(!found){
            if(f->next == breakblock){
                f->next = f->next -> next;
                found = 1;
                break;
            }
            if(f->next == &free_list_heads[orig - ORDER_MIN]){
                break;
            }
            f = f->next;
    }



        breakblock -> next = free_list_heads[orig - 1 - ORDER_MIN].next;
        breakblock -> prev = free_list_heads[orig - 1 - ORDER_MIN].prev;
        free_list_heads[orig - 1 - ORDER_MIN].next = breakblock;

    }
    free_list_heads[get_block_ord(*breakblock) - ORDER_MIN].next = free_list_heads[get_block_ord(*breakblock) - ORDER_MIN].next -> next;
    breakblock -> header.allocated = 1;
    breakblock -> header.rsize = rsize;
    if(rsize + sizeof(bud_header) < ORDER_TO_BLOCK_SIZE(breakblock -> header.order) ){
        breakblock -> header.padded = 1;
    }


    return breakblock;
}

/*
 * Finds next free Block in specific list
 * If none, Returns NULL
 */
void *find_next_free(bud_free_block *list){

    if(list -> next == list){
        return NULL;
    }

    return list -> next;
}


uint64_t get_block_ord(bud_free_block block){
    return block.header.order;

}



void *bud_realloc(void *ptr, uint32_t rsize) {

    // Verify rsize
    if(!rsize){
        bud_free(ptr);
        return NULL;
    }
    if(rsize > MAX_BLOCK_SIZE - sizeof(bud_header)){
        errno = EINVAL;
        return NULL;
    }

    // Verify ptr
    if(ptr == NULL){
        return bud_malloc(rsize);
    }
    if(!valid_header(ptr))
        abort();

    bud_free_block* p = (bud_free_block *)((char *) ptr - sizeof(bud_header));
    int new_ord = ORDER_MIN;

    while(ORDER_TO_BLOCK_SIZE(new_ord) < rsize + sizeof(bud_header))
        new_ord++;

    //New order is same size as current block
    if(p -> header.order == new_ord)
        return ptr;


    if(p -> header.order < new_ord){
        void * new_block = bud_malloc(rsize);
        memcpy(new_block, ptr, p ->header.rsize);
        bud_free(ptr);
        return new_block;
    }

    //bud_free_block b = (bud_free_block *) p;
    if(p -> header.order > new_ord){

        char * ret = bud_break_up(new_ord, p, rsize);
        ret += sizeof(bud_header);
        return ret;
    }




    return NULL;
}

void bud_free(void *ptr) {

    // Verify ptr
    if(!valid_header(ptr))
        abort();


    bud_free_block* p = (bud_free_block *)((char *) ptr - sizeof(bud_header));
    p-> header.allocated = 0;

    bud_free_block* bud = (bud_free_block *)((uint64_t)p ^(ORDER_TO_BLOCK_SIZE(p->header.order) ));

    if(!bud ->header.allocated && bud ->header.order == p->header.order){ //Buddy is Free

        while(!bud ->header.allocated && bud ->header.order == p->header.order){

            p = (bud_free_block *)coalesce_bud(p,bud);
            bud = (bud_free_block *)((uint64_t)p ^(ORDER_TO_BLOCK_SIZE(p->header.order)));


        }


    }else{ //Buddy is not free


        p -> next = free_list_heads[p->header.order - ORDER_MIN].next;
        p -> prev = free_list_heads[p->header.order  - ORDER_MIN].prev;
        free_list_heads[p->header.order  - ORDER_MIN].next = p;



    }
    return;
}



void *coalesce_bud(bud_free_block *p, bud_free_block *bud){
    int found = 0;
    bud_free_block *f = &free_list_heads[bud->header.order - ORDER_MIN];
    while(!found){
        if(f->next == bud){
            f->next = f->next -> next;
            found = 1;
            break;
        }
        f = f->next;
    }


    //free_list_heads[bud->header.order - ORDER_MIN].next = free_list_heads[bud ->header.order - ORDER_MIN].next -> next;
       bud_free_block *low;
       bud_free_block *high;
       if(bud < p){
            low = bud;
            high = p;
       }
        else {
            low = p;
            high = bud;
        }

        found = 0;
        f = &free_list_heads[low->header.order - ORDER_MIN];
        while(!found){
            if(f->next == low){
                f->next = f->next -> next;
                found = 1;
                break;
            }
            if(f->next == &free_list_heads[low->header.order - ORDER_MIN]){
                break;
            }
            f = f->next;
        }


        found = 0;
        f = &free_list_heads[high->header.order - ORDER_MIN];
        while(!found){
            if(f->next == high){
                f->next = f->next -> next;
                found = 1;
                break;
            }
            if(f->next == &free_list_heads[high->header.order - ORDER_MIN]){
                break;
            }
            f = f->next;
        }






        low -> header.order++;



        low -> next = free_list_heads[low->header.order - ORDER_MIN].next;
        low -> prev = free_list_heads[low->header.order - ORDER_MIN].prev;
        free_list_heads[low->header.order - ORDER_MIN].next = low;
        return low;

}



/*
 * Verifies Pointer FIX THIS LATER
 */
int valid_header(void *ptr){


    if(ptr > bud_heap_end() || ptr < bud_heap_start())
        return 0;

    if( (uint64_t)ptr % 8!= 0)
       return 0;

    bud_header* p = (bud_header *)((char *) ptr - sizeof(bud_header));


    if (p -> order < ORDER_MIN || p-> order >= ORDER_MAX )
        return 0;
    if (!p -> allocated)
        return 0;
    if (!p -> padded && p->rsize + sizeof(bud_header) != ORDER_TO_BLOCK_SIZE(p-> order))
        return 0;
    if (p -> padded && p->rsize + sizeof(bud_header) == ORDER_TO_BLOCK_SIZE(p-> order))
        return 0;


    int actual_ord = ORDER_MIN;
    while(ORDER_TO_BLOCK_SIZE(actual_ord) < p ->rsize + sizeof(bud_header))
        actual_ord++;
    if(actual_ord != p -> order)
        return 0;




    return 1;

}
