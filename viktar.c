#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<stdlib.h> //gives u exits success and failure
#include<stdint.h>
#include<md5.h>
#include<sys/types.h>
#include<pwd.h> //gives you getpwuid()
#include<grp.h> //gives you getgrgid()
#include<sys/stat.h>
#include<fcntl.h>
#include<time.h>
#include"viktar.h"

#define BUF_SIZE 100

//function prototypes
void long_table_contents(char *filename);
void short_table_contents(char *filename);
void print_permissions(mode_t mode);
void create_archive(char *filename,int fd,int argc, char *argv[]);
void extract_archive(char *filename,int argc, char *argv[]);
int validate_file(char *filename);
void validate_archive(char *filename);

int 
main(int argc, char *argv[]){
    //variables
    //char *file_names;
    char *filename = NULL;
    int fd = 0;
    viktar_action_t mode = ACTION_NONE;
    //mode_t old_mode = 0;
    //ssize_t bytes_read;

    //parse command line using get opt
    {
        int option = 0;

        while((option = getopt(argc,argv,OPTIONS)) != -1){
            switch(option)
            {
                //extract members from viktar file
                case'x':
                    mode = ACTION_EXTRACT;
                    break;
                case'c': //create an archive file
                    mode = ACTION_CREATE;
                    break;
                case't'://short table of contents
                    mode = ACTION_TOC_SHORT;
                    break;
                case'T'://Long table of contents
                    mode = ACTION_TOC_LONG;
                    break;
                case'f'://specify the name of the viktar file on 
                        //which to operate
                    filename = optarg;
                    break;
                case'V'://Validate the content of archive member with 
                        //the CRC values
                    mode = ACTION_VALIDATE;
                    break;
                case'h'://show help and exit
                    fprintf(stdout, "help text\n");
					fprintf(stdout, "\t./viktar\n");
					fprintf(stdout, "\tOptions: xctTf:Vhv\n");
					fprintf(stdout, "\t\t-x\t\textract file/files from archive\n");
					fprintf(stdout, "\t\t-c\t\tcreate an archive file\n");
					fprintf(stdout, "\t\t-t\t\tdisplay a short table of contents of the archive file\n");
					fprintf(stdout, "\t\t-T\t\tdisplay a long table of contents of the archive file\n");
					fprintf(stdout, "\t\tOnly one of xctTV can be specified\n");
					fprintf(stdout, "\t\t-f filename\tuse filename as the archive file\n");
					fprintf(stdout, "\t\t-V\t\tvalidate the MD5 values in the viktar file\n");
					fprintf(stdout, "\t\t-v\t\tgive verbose diagnostic messages\n");
					fprintf(stdout, "\t\t-h\t\tdisplay this AMAZING help message\n");
                    exit(EXIT_SUCCESS);
                    break;
                case'v':
                    fprintf(stderr,"VERBOSE is enabled\n");
                    break;
                default:
                    break;
            }

        }
    }

    if(mode == ACTION_TOC_SHORT){
        validate_file(filename);
        short_table_contents(filename);
    }
    if(mode == ACTION_TOC_LONG){
        if(filename != NULL){
            //only need to open file not std_in
            fd = open(filename, O_RDONLY); //get file descriptor of file

            if(fd < 0){
                fprintf(stderr,"Cannot open %s for input\n",filename);
                exit(EXIT_FAILURE);
            }
        }
        else{
            printf("reading archive from stdin\n");
        }
        //need to check if there filename was passed or not
        long_table_contents(filename);
    }

    //create file
    if(mode == ACTION_CREATE){
        create_archive(filename,fd,argc,argv);
    }

    if(mode == ACTION_EXTRACT){
        extract_archive(filename,argc,argv);
    }
    
    if(mode == ACTION_VALIDATE){
        validate_archive(filename);
    }
    
    //close file descriptor
    close(fd);

    return(EXIT_SUCCESS);
}

void validate_archive(char *filename){
    //variables 
    int fd = validate_file(filename);
    //unsigned char buf[BUF_SIZE];
    ssize_t bytes_read;
    //ssize_t remaining_bytes;
    int header_matches = FALSE;
    int data_matches = FALSE;
    viktar_header_t header;
    viktar_footer_t footer;
    MD5_CTX header_context;
    MD5_CTX data_context;
    unsigned char header_result[MD5_DIGEST_LENGTH];
    unsigned char data_result[MD5_DIGEST_LENGTH];
    int file_count = 0;
    unsigned char *big_gulp = NULL;

    //read file
    while((bytes_read = (read(fd, &header,sizeof(viktar_header_t))) > 0)){
        ++file_count;
        printf("Validation for data member %d:\n",file_count);
        
        //calculate the md5's for header and data
        MD5Init(&header_context);
        MD5Update(&header_context, (uint8_t *)&header, sizeof(header));
        MD5Final(header_result, &header_context);
        //lseek to the footer data
        //lseek(fd, header.st_size, SEEK_CUR);
        //lseek(fd,sizeof(viktar_footer_t),SEEK_END);//seek to end

	big_gulp = realloc(big_gulp, header.st_size);
	read(fd, big_gulp, header.st_size);
	
        //read footer data
        read(fd, &footer,sizeof(viktar_footer_t));
        
        MD5Init(&data_context);
        MD5Update(&data_context, big_gulp, header.st_size);
        MD5Final(data_result, &data_context);

        //compare the header 
        if(memcmp(header_result,footer.md5sum_header,MD5_DIGEST_LENGTH) != 0){
            //print to stdout. so I can just use printf
            printf("\t*** Header MD5 does not match:\n");
            header_matches = FALSE;
        }
        else{
            printf("\tHeader MD5 does match:\n");
            header_matches = TRUE;
        }

        //print out header_result (found)
        printf("\t\tfound:\t");
        for(int i  = 0; i < MD5_DIGEST_LENGTH;++i){
            printf("%02x",header_result[i]);
        }
        printf("\n");
        
        //print in-file header
        printf("\t\tin file:\t");
        for(int i  = 0; i < MD5_DIGEST_LENGTH;++i){
            printf("%02x",footer.md5sum_header[i]);
        }
        printf("\n");
        

        //print out in file (in file:

        //compare the data MD5
        if(memcmp(data_result,footer.md5sum_data,MD5_DIGEST_LENGTH) != 0){
            printf("\t*** Data MD5 does not match:\n");
            data_matches = FALSE;
        } 
        else {
            printf("\tData MD5 does match:\n");
            data_matches = TRUE;
        }

        printf("\t\tfound:\t");
        for(int i  = 0; i < MD5_DIGEST_LENGTH;++i){
            printf("%02x",data_result[i]);
        }
        printf("\n");

        //print out in file (in file:
        printf("\t\tin file:");
        for(int i  = 0; i < MD5_DIGEST_LENGTH;++i){
            printf("%02x",footer.md5sum_data[i]);
        }
        printf("\n");

        //check if both failed
        if(!data_matches || !header_matches){
            printf("*** Validation failure: %s for member %d\n", filename ? filename : "stdin", file_count);
        }
    }
    
    if (big_gulp) {
      free(big_gulp);
    }

    if( fd != STDIN_FILENO){
        close(fd);
    }
}

//this function extracts members from archive file.
void extract_archive(char *filename,int argc,char *argv[])
{
    //variables
    int files_specified = FALSE;
    unsigned char buf[BUF_SIZE] = {'\0'};
    char buffer[BUF_SIZE] = {'\0'};
    char member_file[VIKTAR_MAX_FILE_NAME_LEN + 1]; // +1 for null terminator
    //int fd = validate_file(filename);
    int fd = 0;
    viktar_header_t header;
    viktar_footer_t footer;
    int extract = TRUE;
    
    if(filename != NULL){
        fd = open(filename,O_RDONLY);
    }
    else{
        filename = "stdin";
        fprintf(stderr,"reading archive from stdin");
    }

     //read from file or command line
    read(fd, buffer, strlen(VIKTAR_TAG));

    //check if it matches the same number of bytes as VIKTAR TAG
    if(strncmp(buffer, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0) {
        fprintf(stderr, "not a viktar file: \"%s\"\n",filename);
        exit(EXIT_FAILURE);
    }


    //check if user input specific files to extract from archive
    if(optind < argc){
        files_specified = TRUE; 
    }


    //read file loop (archive file)
    while(read(fd, &header, sizeof(viktar_header_t)) > 0){
        //extract filename
        memcpy(member_file,header.viktar_name,VIKTAR_MAX_FILE_NAME_LEN);
        member_file[VIKTAR_MAX_FILE_NAME_LEN] = '\0';

        //if not extracting all member files
        if(files_specified){
            //loop through each extra command line arg
            for(int i = optind;i < argc;++i){
                //check if filename is in archive
                if(strcmp(member_file,argv[i]) == 0){
                    extract = TRUE;
                }
                else{
                    extract = FALSE;
                }
            }
        }
        if(extract){
            //extract current file
            //variables
            ssize_t bytes_read = 0;
            int new_fd = 0;
            struct timespec times[2];
            MD5_CTX foot_context;
            unsigned char md5_sum[MD5_DIGEST_LENGTH];
            int content_bytes = header.st_size;

            //create the file to extract contents into 
            new_fd = open(member_file,O_WRONLY | O_CREAT | O_TRUNC, header.st_mode);

            //check if it opened correctly
            if(new_fd < 0){
                perror("Error creating output file\n");
                exit(EXIT_FAILURE);
            }

            //set permissions of file to extracted file
            fchmod(new_fd,header.st_mode);
            
            //initialize foot context
            MD5Init(&foot_context);
            
            //read the contents of the file
            while((bytes_read = read(fd,buf,(content_bytes < BUF_SIZE) ? content_bytes :BUF_SIZE)) > 0){
                //write to the new file
                //write(new_fd,buf,content_bytes);
                write(new_fd,buf,bytes_read); //trying this
                //subtract bytes that way on the next loop you only read whats left
                //if its bigger than the buf size
                content_bytes = content_bytes - bytes_read;
                //update MD5
                MD5Update(&foot_context,buf, bytes_read);
            }
            MD5Final(md5_sum,&foot_context);

            //read the footer
            read(fd,&footer,sizeof(viktar_footer_t));
            //validate MD5 checksum against the footer
            if (memcmp(md5_sum, footer.md5sum_data, MD5_DIGEST_LENGTH) != 0)
            {
                //fprintf(stderr, "Warning: MD5 checksum mismatch detected for file '%s'. \n", header.viktar_name);
            }

            //restore the timestamps on the extracted file
            times[0] = header.st_atim;
            times[1] = header.st_mtim;

            //set the access and modify times to the newly created file
            futimens(new_fd,times);

            close(new_fd);
        }
        else{
            //skip file and move to the next
            lseek(fd,header.st_size + sizeof(viktar_footer_t),SEEK_CUR);
        }

    }
    //close archive file descriptor
    close(fd);
}

//this function create the archive file
void create_archive(char *filename,int fd,int argc, char *argv[]){
    //variables
    viktar_header_t header;//struct to copy file header info into 
    viktar_footer_t footer;//struct to copy file header info into 
    struct stat file_stat;
    unsigned char buf[BUF_SIZE] = {'\0'};
    ssize_t bytes_read;
    //int fd = validate_file(filename);
    MD5_CTX head_context;
    MD5_CTX foot_context;

    //open the archive file, if filename is provided, else use stdout
    if(filename){
        fd = open(filename, O_WRONLY |O_TRUNC | O_CREAT
                ,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if(fd < 0){
            perror("Cannot create archive file");
            exit(EXIT_FAILURE);
        }
    }
    else{
        //no filename specified, default to stdout
        fd = STDOUT_FILENO; //same as 0
    }

    //write tag to create archive file.
    write(fd,VIKTAR_TAG,strlen(VIKTAR_TAG));

    //ADDING MULTIPLE FILES TO THE ARCHIVE
    //if theres any files enter to put into the archive file
    //they would be in argc
    if(optind < argc){ //if true, means additnal args in the argv.
        for(int i = optind; i < argc;i++){
            //open each file and read its metadata
            int input_fd = open(argv[i], O_RDONLY);
            if(input_fd < 0){
                fprintf(stderr,"Error opening file");
                exit(EXIT_FAILURE);
            }

            //prepare header,filecontent,and footer for each file
            strncpy(header.viktar_name,argv[i],VIKTAR_MAX_FILE_NAME_LEN);

            fstat(input_fd, &file_stat);
            //copy all info over to header
            header.st_size = file_stat.st_size;
            header.st_mode = file_stat.st_mode;
            header.st_uid = file_stat.st_uid;
            header.st_gid = file_stat.st_gid;
            header.st_atim = file_stat.st_atim;
            header.st_mtim = file_stat.st_mtim;
            //compute MD5 checksum for the header
            MD5Init(&head_context);//initialize
            MD5Update(&head_context,(const uint8_t *)&header,sizeof(viktar_header_t));//update
            MD5Final(footer.md5sum_header,&head_context);
            

            //write header to archive
            write(fd,&header,sizeof(viktar_header_t));
    
            //i think we need to clear out context and digest before we use
            //them again
            MD5Init(&foot_context);//initialize

            //write data (actual file content)
            while((bytes_read = read(input_fd,buf,BUF_SIZE)) > 0){
                write(fd,buf,bytes_read);
                MD5Update(&foot_context,buf,bytes_read);
            }
            MD5Final(footer.md5sum_data,&foot_context);
            
            //write to the footer
            write(fd,&footer,sizeof(viktar_footer_t));

            close(input_fd);
        }

        //if there are no addtional arguments(filenames to add)
        //were done
    }

    //close(fd);
    //make note of permission on the new file
}

int validate_file(char *filename){
    //variables
    int fd = STDIN_FILENO; 
    char buf[BUF_SIZE] = {'\0'};

    //if archive file was set as a command line argument
    if(filename != NULL){
        fprintf(stderr, "reading archive file: \"%s\"\n", filename);

        //only need to open file not std_in
        fd = open(filename, O_RDONLY); //get file descriptor of file

        if(fd < 0){
            fprintf(stderr,"Cannot open %s for input\n",filename);
            exit(EXIT_FAILURE);
        }
    }
    else{
        fprintf(stderr,"reading archive from stdin\n");
    }

    //read from file or command line
    read(fd, buf, strlen(VIKTAR_TAG));
    //buf[strlen(VIKTAR_TAG)] = '\0';//null terminate the string

    //check if it matches the same number of bytes as VIKTAR TAG
    if(strncmp(buf, VIKTAR_TAG, strlen(VIKTAR_TAG)) != 0) {
        // not a valid viktar file
        // print snarky message and exit(1).
        fprintf(stderr, "not a viktar file: \"%s\"\n",filename!= NULL ? filename : "stdin");
        exit(EXIT_FAILURE);
    }
    
    //return file descriptor
    return fd;
}

void print_permissions(mode_t mode){
    printf("%c",(mode & S_IRUSR) ? 'r' : '-');
    printf("%c",(mode & S_IWUSR) ? 'w' : '-');
    printf("%c",(mode & S_IXUSR) ? 'x' : '-');
    printf("%c",(mode & S_IRGRP) ? 'r' : '-');
    printf("%c",(mode & S_IWGRP) ? 'w' : '-');
    printf("%c",(mode & S_IXGRP) ? 'x' : '-');
    printf("%c",(mode & S_IROTH) ? 'r' : '-');
    printf("%c",(mode & S_IWOTH) ? 'w' : '-');
    printf("%c",(mode & S_IXOTH) ? 'x' : '-');
    printf("\n");
}

//displays the short table of contents
void short_table_contents(char *filename)
{
    //variables
    viktar_header_t md;
    char buf[BUF_SIZE] = {'\0'};
    int fd = validate_file(filename);

    printf("Contents of viktar file: \"%s\"\n"
            ,filename!= NULL ? filename : "stdin");

    while(read(fd, &md,sizeof(viktar_header_t)) > 0){
        memset(buf, 0,100);
        strncpy(buf,md.viktar_name, VIKTAR_MAX_FILE_NAME_LEN);
        //print archive member name
        printf("\tfile name: %s\n",buf);
        lseek(fd,md.st_size + sizeof(viktar_footer_t),SEEK_CUR);
    }
    //close the file descriptor
    close(fd);
}

//displays the long table of contents
void long_table_contents(char *filename)
{
    //variables
    char buf[BUF_SIZE] = {'\0'};
    viktar_header_t md; 
    viktar_footer_t foot;
    struct passwd* pw; //to hold user info
    struct group* gruid; //to hold group info
    char time_string[BUF_SIZE];
    struct tm* mtime;
    struct tm* atime;
    int fd = validate_file(filename);

    printf("Contents of viktar file: \"%s\"\n"
            ,filename!= NULL ? filename : "stdin");

    while(read(fd, &md,sizeof(viktar_header_t)) > 0){
        memset(buf, 0,100);
        strncpy(buf,md.viktar_name, VIKTAR_MAX_FILE_NAME_LEN);
        //print archive member name
        printf("\tfile name: %s\n",buf);

        //mode
        printf("\t\tmode:\t\t-");
        print_permissions(md.st_mode);

        //user id
        pw = getpwuid(md.st_uid);
        printf("\t\tuser:\t\t%s\n", pw ? pw->pw_name : "noID");

        //group
        gruid = getgrgid(md.st_gid);
        printf("\t\tgroup:\t\t%s\n", gruid ? gruid->gr_name: "noGroup");

        //size
        printf("\t\tsize:\t\t%ld\n",md.st_size);

        //mtime
        //converts the last modified time into a struct tm
        //breaks down the timestamp. tv_sec is seconds after
        //epoch.
        mtime = localtime(&md.st_mtim.tv_sec);
        strftime(time_string,sizeof(time_string),"%Y-%m-%d %H:%M:%S %Z",mtime);
        printf("\t\tmtime:\t\t%s\n",time_string);

        //atime
        atime = localtime(&md.st_atim.tv_sec);
        strftime(time_string,sizeof(time_string),"%Y-%m-%d %H:%M:%S %Z",atime);
        printf("\t\tatime:\t\t%s\n",time_string);

        lseek(fd,md.st_size,SEEK_CUR);

        //footer section
        read(fd,&foot,sizeof(viktar_footer_t));
        //md5 sum header
        printf("\t\tmd5 sum header:\t");
        for(int i =0; i < MD5_DIGEST_LENGTH; i++){
            printf("%02x",foot.md5sum_header[i]);
        }
        printf("\n");

        //md5 sum data
        printf("\t\tmd5 sum data:\t");
        for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
            printf("%02x",foot.md5sum_data[i]);
        }
        printf("\n");

    }
    close(fd);
}
