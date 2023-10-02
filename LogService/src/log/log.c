#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define SIZE 64
#define MAX_REQUESTS 50

//menu macro
#define ADD_REQUEST 0 
#define SHOW_REQUEST 1 
#define REMOVE_REQUEST 2 
#define SAVE_LOG 3
#define IMPORT_LOG 4
#define EXIT 5

#define OK 0
#define INV 1
#define ERR 2
#define MENU 100

char **requests=0;
int n_requests=0;
unsigned int *r_sizes;

void init();
int menu();
void import_log();
void save_log();
void add_request();
void show_request();
void remove_request();
void send_message(int code, unsigned int size, char *message);

int main(){
    int choice;
    init();

    while(1){
        choice = menu();

        switch(choice){
            case IMPORT_LOG:
                import_log();
                break;
            case SAVE_LOG:
                save_log();
                break;
            case ADD_REQUEST:
                add_request();
                break;
            case SHOW_REQUEST:
                show_request();
                break;
            case REMOVE_REQUEST:
                remove_request();
                break;
            case EXIT:
                send_message(OK, 7, "bye bye");
                exit(0);
                break;
            default:
                send_message(INV, 14, "invalid choice");
                break;
        }
    }
}

void init(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int menu(){
    send_message(MENU, 2, "> "); 
    
    int act;
    fread(&act, sizeof(int), 1, stdin); 
    return act;
}


void import_log(){
    send_message(ERR, 38, "this feature has yet to be implemented"); 
}

void show_request(){
    unsigned int idx;
    fread(&idx, sizeof(unsigned int), 1, stdin);
    if(idx>=n_requests){
        send_message(INV, 11, "invalid idx");
        return;
    }
    send_message(OK, r_sizes[idx], requests[idx]);
}

void save_log(){
    FILE *f = fopen("default", "ab");
    if(!f){
        send_message(ERR, 19, "opening file failed");
        return ;
    }
    for(int i=0; i<n_requests; i++){
        int length = r_sizes[i];
        fwrite(&length, sizeof(int), 1, f); 
        fwrite(requests[i], sizeof(char), length, f); 
    }
    fclose(f);
    send_message(OK, 2, "OK");
}

void remove_request(){
    unsigned int idx;
    fread(&idx, sizeof(unsigned int), 1, stdin);

    if(idx>=n_requests){
        send_message(INV, 11, "invalid idx");
        return;
    }
    free(requests[idx]);

    //Shift elements from x+1 to the end one position to the left
    for (int i = idx; i < n_requests- 1; i++) {
        requests[i] = requests[i + 1];
    }
    send_message(OK, 2, "OK");
}

void clear_stdin(){
    while (getchar() != EOF);   //; is not a mistake
}


void add_request(){
    unsigned int sz;
    if(n_requests==MAX_REQUESTS){
        send_message(INV, 30, "Max number of requests reached");
        clear_stdin();
        return;
    }
    fread(&sz, sizeof(unsigned int), 1, stdin);
    if(sz > 0x1000){
        send_message(INV, 12, "invalid size");
        clear_stdin();
        return;
    }
    char *r = malloc(sz);
    if(r){
        n_requests += 1;
        requests = realloc(requests, n_requests*sizeof(char *));
        r_sizes = realloc(r_sizes, n_requests*sizeof(unsigned int));
        r_sizes[n_requests-1]=sz;
        fread(r, sizeof(char), sz, stdin);
        requests[n_requests-1]=r;
        send_message(OK, 2, "OK");
    }
    else{
        send_message(ERR, 13, "malloc failed");
        clear_stdin();
        n_requests-=1;
    }
}

void send_message(int code, unsigned int size, char *message){
    fwrite(&code, sizeof(int), 1, stdout); 
    fwrite(&size, sizeof(int), 1, stdout); 
    fwrite(message, sizeof(char), size, stdout);
}

/*useless feature
void change_log(){
    printf("insert log name: ");
    fgets(log_name, SIZE, stdin);
    size_t length = strlen(log_name);
    if(buffer[length-1]=='\n')
        buffer[length-1]=0;
    is_log=1;
}
*/
