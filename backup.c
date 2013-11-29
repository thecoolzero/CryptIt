#define FUSE_USE_VERSION 26
#include <dirent.h>
#include <fuse_lowlevel.h>
#include <fuse.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include "errors.h"

#define PRDATA ((crypt_data*)(fuse_get_context()->private_data))

typedef struct crypt_data
{
	char* path;
	char *pass;
} crypt_data;




int getnum ( char* num )
{
	return (num[0]-'0')*10+num[1]-'0';
}

void int2str(int number, char* ret ) 
{
	ret[0] = number/10 + '0';
	ret[1] = (number%10) + '0';
	ret[2] = 0;
}


int getpasslength()
{
	return strlen(PRDATA->pass);
}

int checkAccess( const char* pass ) 
{
	/////// CHECK IF HAS PROVIDED PROPER PASS ////////
	return !strcmp( pass, PRDATA->pass );
}

static int crypt_readdir(const char* path,void* buf,fuse_fill_dir_t filler,off_t offset,struct fuse_file_info *fi)
{
	DIR* dp;
	struct dirent *entry;
	if(fi && fi->fh)
		dp = (DIR*)(uintptr_t)fi->fh;
	else return 0;
	entry = readdir (dp);
	if ( !entry ) return -errno;
	do 
		if (filler(buf,entry->d_name,NULL,0)) return -ENOMEM;
	while (entry = readdir ( dp ));

	return 0;

}

static int crypt_getattr(const char* path,struct stat *stbuf)
{
	char rootpath[100];
	strcpy(rootpath,PRDATA->path);
	int res = lstat(strcat(rootpath,path),stbuf);
	if ( res == -1 ) return -errno;
	return res;

}

static int crypt_opendir (const char* path, struct fuse_file_info *fi)
{
	char rootpath[100];
	strcpy(rootpath, PRDATA->path);
	DIR* dp = opendir( strcat(rootpath,path) ) ;
	fi->fh = dp;
	return 0;
}
static int crypt_access ( const char* path,int mask)
{
	char rootpath[100];
	strcpy(rootpath,PRDATA->path);
	return access(strcat(rootpath,path),mask);
}


static int crypt_create (const char* path ,mode_t mode, struct fuse_file_info *fi) 
{
	char rootpath[100];
	strcpy(rootpath,PRDATA->path);
	int fd = creat( strcat(rootpath,path) , mode);
	if ( fd < 0 )return -errno;
	fi->fh = fd;
	char passlength[3];
	int2str(strlen(PRDATA->pass),passlength);
	pwrite ( fd,passlength,2,0);
	pwrite ( fd,PRDATA->pass,getpasslength(),2);
	return 0;
}


static int crypt_read(const char* path,char* buf,size_t size,off_t offset,struct fuse_file_info *fi)
{
	char rootpath[100];
	strcpy(rootpath, PRDATA->path);
	strcat (rootpath , path) ;
	char sz[3];
	int res = read ( rootpath,sz,2 );
	int num = 0;
	if ( res == 2 ) num = getnum(sz);
	char buffer[100];
	int ret=0;
	int start = 0;
        if ( offset < 2+num ) start = 2+num;	
	ret = pread ( fi->fh , buffer, size,start+offset );
	char M[50];
	strcpy(M,PRDATA->pass);
	int i;
	for (i=0;i<ret;i++)
		buf[i] = (char)((int)buffer[i] ^ (int) M[(offset+i)%strlen(M)] );
	return ret;
}

static int crypt_open(const char * path,struct fuse_file_info *fi)
{
	char rootpath[100];
	strcpy(rootpath,PRDATA->path);
	int fd = open( strcat(rootpath,path) , fi->flags);
	if ( fd < 0 )return -errno;
	fi->fh = fd;
	return 0;
}

static int crypt_write(const char* path , const char * buf,size_t size, off_t offset,struct fuse_file_info* fi )
{
	char rootpath[100];
	strcpy(rootpath, PRDATA->path) ;
	int fd = open ( strcat(rootpath,path) , O_RDWR );
	char passlength[3];
	int2str(getpasslength(),passlength);
	//CHECK FOR CORRECT PASS
	/*char sz[3];
	int res ; 
	res = pread ( fd , sz, 2 ,0) ;
	int num = 0 ;
	if (res != 2 ) 
	{
		close(fd) ;
		return -errno;
	}
	num = genum(sz);
	char buffer [100];*/
	
	if ( fd < 0 ) return -errno;
	char *towrite = (char*) malloc ( (size+10) * sizeof( char ) );
	int i;
	for (i = 0 ; i < size ; i++)
		towrite [i] = buf[i] ^ PRDATA->pass[ (i + offset)%strlen(PRDATA->pass) ] ; 
	towrite[size] = 0;
	int res = pwrite ( fd,towrite,size,offset);
	if ( res < 0 ) res = -errno;
	close(fd);
	return res;
}

static struct fuse_operations cryp = 
{
	.getattr = crypt_getattr ,
	.readdir = crypt_readdir ,
	.opendir = crypt_opendir,
	.access = crypt_access,
	.create = crypt_create,
	.open = crypt_open,
	.read = crypt_read,
	.write = crypt_write,
};

int main(int argc,char *argv[])
{
	int toEnc = 0;
	
	//////////////////////////HANDLE PROGRAM ARGUMENTS////////////////////////////
	while ( argc>3 && argv[argc-1][0] == '-' ) 
	{
		if ( !strcmp(argv[argc-1],"-e") ){toEnc = 1;argv[--argc] = NULL;}
		else return UNKARG;
	}
	//////////////////////ERROR HANDLING ON ARGUMENTS/////////////////////////////
	if ( argc < 3 ) 
	{
		fprintf(stderr,"You need more arguments to call the program\n");
		fprintf(stderr,"crypt [FUSE OPTIONS] mountdir rootdir [OPTIONS]\n");
		return NOENOARG;
	}
	if ( ! strcmp(argv[argc-1],argv[argc-2] ) )
	{
		fprintf(stderr,"root dir and mount dir cannot be the same\n") ;
		return SAMEDIRS;
	}
	/////////// RUN EITHER FOR START AN ENCRYPTION OR USE AN EXISTING ONE ////////////////
	if ( !toEnc )
	{
		char path[100];
		crypt_data data;
		printf("You Havent Provided The Password For This FileSystem Yet, Please Enter The Password : ");
		sprintf( path , "%s",realpath(argv[--argc],NULL) );
		char pass[100];
		scanf("%s",pass);
		printf("So bad, You Haven't got the correct password\n");
		data.path = path;
		data.pass = pass;
		char ret[3];
		int2str(strlen(data.pass),ret);
		printf("%s\n",ret);
		return fuse_main(argc,argv,&cryp,&data);
	}
	else {;} 
	//////////////////////////////////////////////////////////////////////////////////////

}
