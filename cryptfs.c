#define FUSE_USE_VERSION 26
#include <dirent.h>
#include <fuse_lowlevel.h>
#include <fuse.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include "errors.h"
#include <openssl/sha.h>

#define MAXPASSLENGTH 150
#define PRDATA ((crypt_data*)(fuse_get_context()->private_data))

typedef struct crypt_data
{
	char *path;
	char *pass;
	char* rawpass;
	int *start;
	int* headersize;
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
	char fullpath[4096];
	strcpy(fullpath,PRDATA->path);
	/*char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	int fd = open ( fullpath,O_RDONLY );
	if ( fd < 0 ) return -errno;
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	*/
	int res = lstat(strcat(fullpath,path),stbuf);
	if ( res == -1 ) return -errno;
	return res;

}

static int crypt_opendir (const char* path, struct fuse_file_info *fi)
{
	char fullpath[4096];
	strcpy(fullpath, PRDATA->path);
	DIR* dp = opendir( strcat(fullpath,path) ) ;
	fi->fh = dp;
	return 0;
}
static int crypt_access ( const char* path,int mask)
{
	struct stat st_buf;
	char fullpath[4096];
	strcpy(fullpath,PRDATA->path);
	strcat(fullpath,path);
	stat ( fullpath, &st_buf) ;
	if ( S_ISREG(st_buf.st_mode) )
	{
			char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
		int fd = open ( fullpath,O_RDONLY );
		if ( fd < 0 ) return -errno;
		read( fd , filepass, *(PRDATA->headersize));
		close(fd);
		if (!checkAccess ( filepass)) 
			return -PERDENIED;
	}
	return access(fullpath,mask);
}


static int crypt_create (const char* path ,mode_t mode, struct fuse_file_info *fi) 
{
	char fullpath[4096];
	strcpy(fullpath,PRDATA->path);
	int fd = creat( strcat(fullpath,path) , mode);
	if ( fd < 0 )return -errno;
	fi->fh = fd;
	pwrite ( fd,PRDATA->pass,getpasslength(),0);
	*(PRDATA->start) = *(PRDATA->headersize);
	return 0;
}


static int crypt_read(const char* path,char* buf,size_t size,off_t offset,struct fuse_file_info *fi)
{
	char fullpath[4096];
	strcpy(fullpath, PRDATA->path);
	strcat (fullpath , path) ;
	int fd = open ( fullpath , O_RDONLY);
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	char *buffer = calloc ( size+10,sizeof(char));
	int ret=0;
	int start = 0;
        if ( offset < *(PRDATA->headersize) ) start = getpasslength();	
	ret = pread ( fi->fh , buffer, size,start+offset );
	char M[MAXPASSLENGTH];
	strcpy(M,PRDATA->rawpass);
	int i;
	for (i=0;i<ret;i++)
		buf[i] = (char)((int)buffer[i] ^ (int) M[(offset+i)%strlen(M)] );
	return ret;
}

static int crypt_open(const char * path,struct fuse_file_info *fi)
{
	char fullpath[4096];
	strcpy(fullpath,PRDATA->path);
	strcat ( fullpath,path);
	int fd = open ( fullpath, O_RDONLY);
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	fd = open( fullpath , fi->flags);
	if ( fd < 0 )return -errno;
	*(PRDATA->start) = 0;
	fi->fh = fd;

	return 0;
}

static int crypt_write(const char* path , const char * buf,size_t size, off_t offset,struct fuse_file_info* fi )
{
	//char fullpath[4096];
	//strcpy(fullpath, PRDATA->path) ;
	//int fd = open ( strcat(fullpath,path) , O_RDWR | O_TRUNC );
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
	char buffer [4096];*/
	char fullpath[4096];
	strcpy(fullpath,PRDATA->path);
	strcat ( fullpath,path);
	int fd = open ( fullpath, O_RDONLY);
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	if ( offset < *(PRDATA->headersize) )
	{
		pwrite ( fi->fh,PRDATA->pass,getpasslength(),0);
		*(PRDATA->start) = *(PRDATA->headersize);
	}	
	char *towrite = (char*) malloc ( (size+10) * sizeof( char ) );
	int i;
	for (i = 0 ; i < size ; i++)
		towrite [i] = buf[i] ^ PRDATA->rawpass[ (i + *(PRDATA->start)+offset-*(PRDATA->headersize))%strlen(PRDATA->rawpass) ] ; 
	towrite[size] = 0;
	int res = pwrite ( fi->fh,towrite,size,*(PRDATA->start)+offset);
	if ( res < 0 ) res = -errno;
	return res;
}

int crypt_truncate(const char* path,off_t newsize)
{
	char fullpath[4096];
	strcpy(fullpath, PRDATA->path) ;
	strcat ( fullpath,path) ;
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int retstat = truncate( fullpath ,newsize );
	if ( retstat < 0 ) retstat = -errno;  
	return retstat;
}


int crypt_ftruncate(const char * path, off_t newsize,struct fuse_file_info* fi)
{
	int retstat = ftruncate( fi->fh,newsize );
	return retstat;
}


int crypt_setxattr(const char* path,const char* name,const char* value,size_t size,int flags)
{
	char fullpath[4096];
	strcpy(fullpath, PRDATA->path) ;
	strcat(fullpath,path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int retstat = lsetxattr( fullpath ,name,value,size,flags );
	return retstat;
}

int crypt_utime(const char* path , struct utimbuf* ubuf) 
{
	char fullpath[4096];
	strcpy(fullpath, PRDATA->path) ;
	strcat ( fullpath,path );
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int retstat = utime( fullpath ,ubuf );
	return retstat;
}

int crypt_mknod( const char * path, mode_t mode,dev_t dev)
{
	char fullpath[4096];
	strcpy(fullpath,PRDATA->path);
	strcat( fullpath, path) ;
	int retstat;
	if ( S_ISREG ( mode ) )
	{
		retstat = open (fullpath, O_CREAT | O_EXCL | O_WRONLY, mode) ;
		if ( retstat < 0 )
			retstat = -errno;
		else 
		{
			retstat = close( retstat );
			if ( retstat < 0 ) 
				retstat = -errno;
		}
	}
	else if (S_ISFIFO(mode))
	{
		retstat = mkfifo( fullpath,mode ) ;
		if ( retstat < 0) 
			retstat = -errno;
	}
	else
	{
		retstat = mknod ( path,mode, dev) ;
		if (retstat < 0) 
			retstat = -errno;
	}
	return retstat ;
}

int crypt_chmod( const char * path , mode_t mode) 
{
	char fullpath[4096];
	strcpy(fullpath,PRDATA->path);
	strcat(fullpath,path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int ret = chmod( fullpath ,mode );
	if ( ret < 0 ) ret=  -errno;
	return ret;
}

int crypt_rename(const char * path , const char* newpath ) 
{
	char fullpath[4096];
	char fullnewpath[4096];
	strcpy(fullpath,PRDATA->path) ;
	strcat(fullpath,path);
	strcpy(fullnewpath,PRDATA->path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int ret = rename ( fullpath , strcat ( fullnewpath,newpath) );
	if (ret < 0 ) ret = -errno;
	return ret;
}

int crypt_chown ( const char* path , uid_t uid, gid_t gid)
{
	char fullpath [ 4096 ];
	strcpy ( fullpath, PRDATA->path );
	strcat (fullpath,path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int ret = chown ( fullpath , uid,gid) ;
	if (ret < 0 ) ret = -errno ;
	return ret;
}

int crypt_statfs(const char * path,struct statvfs *statv)
{
	struct stat st_buf;
	char fullpath [ 4096 ];
	strcpy(fullpath , PRDATA->path ) ;
	strcat(fullpath,path);
	stat(fullpath,&st_buf);
	if ( S_ISREG(st_buf.st_mode) )
	{
		int fd = open ( fullpath, O_RDONLY );
		char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
		read( fd , filepass, *(PRDATA->headersize));
		close(fd);
		if (!checkAccess ( filepass)) 
			return -PERDENIED;
	}
	int ret = statvfs ( fullpath , statv);
        if ( ret < 0 ) ret = -errno;	
	return ret;
}

int crypt_flush ( const char * path,struct fuse_file_info* fi )
{
	return 0;
}

int crypt_release (const char* path, struct fuse_file_info* fi)
{
	int ret = close( fi->fh );
	if (ret < 0 ) ret = -errno;
	return ret;
}

int crypt_fsync ( const char* path,int datasync,struct fuse_file_info* fi)
{
	int ret  =0 ;
	if ( datasync )
		ret = fdatasync ( fi->fh) ;
	else
		ret = fsync ( fi->fh );
	if ( ret < 0 ) ret = -errno;
	return ret;
}

int crypt_getxattr(const char * path, const char* name , char* value,size_t size)
{
	int ret = 0;
	char fullpath [ 4096 ];
	strcpy ( fullpath , PRDATA->path) ;
	strcat ( fullpath,path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	ret = lgetxattr ( fullpath , name, value,size) ;
	if ( ret < 0 ) ret = -errno;
	return ret;
}

int crypt_listxattr( const char* path, char* list,size_t size) 
{
	char fullpath[4096];
	strcpy ( fullpath, PRDATA->path ) ;
	strcat(fullpath,path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int ret = llistxattr( fullpath ,list, size ) ;
	if ( ret < 0 ) ret= -errno;
	return ret;
}

int crypt_removexattr ( const char* path, const char* name ) 
{
	char fullpath[4096];
	strcpy ( fullpath, PRDATA->path );
	strcat(fullpath,path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int ret = lremovexattr ( fullpath , name ) ;
	if ( ret < 0 ) ret = -errno;
	return ret;
}

int crypt_fsyncdir ( const char* path,int datasync,struct fuse_file_info* fi )
{
	return 0;
}

int crypt_releasedir ( const char *path, struct fuse_file_info* fi ) 
{
	int ret = closedir ( fi->fh );
	if  ( ret < 0 ) ret = -errno;
	return ret;
}

int crypt_mkdir ( const char* path ,mode_t mode)
{
	char fullpath[4096];
	strcpy ( fullpath,PRDATA->path);
	int ret = mkdir ( strcat ( fullpath, path ) , mode ) ;
	if ( ret < 0 ) ret = -errno;
	return ret;
}

int crypt_unlink ( const char* path ) 
{
	char fullpath[4096];
	strcpy ( fullpath, PRDATA->path );
	strcat(fullpath,path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int ret = unlink ( fullpath  );
	if ( ret < 0 ) ret = -errno;
	return ret;
}

int crypt_rmdir ( const char* path )
{
	char fullpath[4096];
	strcpy( fullpath , PRDATA->path) ;
	int ret = rmdir ( strcat ( fullpath , path ) );
	if ( ret < 0 ) ret = -errno;
	return ret;
}

int crypt_fgetattr( const char* path , struct stat* statbuf,struct fuse_file_info* fi)
{
	char fullpath[4096];
	strcpy(fullpath,PRDATA->path);
	strcat(fullpath,path);
	int fd = open ( fullpath, O_RDONLY );
	char* filepass = calloc(*(PRDATA->headersize)+1,sizeof(char));
	read( fd , filepass, *(PRDATA->headersize));
	close(fd);
	if (!checkAccess ( filepass)) 
		return -PERDENIED;
	int ret = fstat ( fi->fh , statbuf );
	if ( ret < 0 ) ret = -errno;
	return ret;
}


void* crypt_init(struct fuse_conn_info *conn)
{
	*(PRDATA->headersize) = getpasslength();
	return PRDATA;
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
	.init = crypt_init,
	.truncate = crypt_truncate,
	.ftruncate = crypt_ftruncate,
	.setxattr = crypt_setxattr,
	.utime = crypt_utime,
	.mknod = crypt_mknod,
	.chmod = crypt_chmod,
	.rename = crypt_rename,
	.chown = crypt_chown,
	.statfs = crypt_statfs,
	.flush = crypt_flush,
	.fsync = crypt_fsync,
	.getxattr = crypt_getxattr,
	.listxattr = crypt_listxattr,
	.removexattr = crypt_removexattr,
	.fsyncdir = crypt_fsyncdir,
	.mkdir = crypt_mkdir,
	.unlink = crypt_unlink,
	.rmdir = crypt_rmdir,
	.release = crypt_release,
	.releasedir = crypt_releasedir,
	.fgetattr = crypt_fgetattr,
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
		char path[4096];
		crypt_data data;
		printf("You Havent Provided The Password For This FileSystem Yet, Please Enter The Password : ");
		sprintf( path , "%s",realpath(argv[--argc],NULL) );
		int* start = (int*) malloc(sizeof(int));
		int* headersize = (int*) malloc(sizeof(int));
		*start = 0;
		char *pass = calloc(MAXPASSLENGTH,sizeof(char));
		scanf("%s",pass);
		
		unsigned char digest[SHA512_DIGEST_LENGTH];
		SHA512((unsigned char*)pass,strlen(pass),(unsigned char*)digest);
		char *mdString= calloc( SHA512_DIGEST_LENGTH*2 + 1, sizeof(char));
		int i;
		for (i=0;i<SHA512_DIGEST_LENGTH;i++) 
			sprintf(mdString+2*i,"%02x",(unsigned int)digest[i]);
		printf("%s\n",mdString);


		//printf("So bad, You Haven't got the correct password\n");
		data.path = path;
		data.pass = mdString;
		data.start = start;
		data.rawpass = pass;
		data.headersize = headersize;
		char ret[3];
		int2str(strlen(data.rawpass),ret);
		printf("%s\n",ret);
		return fuse_main(argc,argv,&cryp,&data);
	}
	else {;} 
	//////////////////////////////////////////////////////////////////////////////////////

}
