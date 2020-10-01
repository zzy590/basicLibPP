#include<iostream>

using namespace std;

int main()
{
	int a[50][50], n, i, sum[4]={0,0,0,0}, b=1, j;
	
	cout<<"Checking whether center element of matrix equals sum of half diagonals"<<endl<<endl;
	cout<<"Enter value of order of matrix is an odd ordered matrix : ";
	cin>>n;
	
	for(i=0; i<n; i++)
	{
		for(int j=0; j<n; j++)
		cin>>a[i][j];
	}
	cout<<endl<<endl;
	
	for(i=0; i<n; i++)
	{
		for(int j=0; j<n; j++)
		cout<<a[i][j]<<" ";
		
		cout<<endl;
	}
	
	for(i=0; i<n/2; i++)
	{
		sum[0]+=a[i][i];
	}
	
	cout<<endl<<"Sum of half diagonal 1 : "<<sum[0]<<endl;
	
	i=n;
	j=-1;
	do
	{
		i--;
		j++;
		sum[1]+=a[i][j];
		b++;
	}while(b<=n/2);
	
	cout<<endl<<"Sum of half diagonal 2 : "<<sum[1]<<endl;

	i=-1;
	j=n;
	b=1;
	do
	{
		i++;
		j--;
		sum[2]+=a[i][j];
		b++;
	}while(b<=n/2);
	
	cout<<endl<<"Sum of half diagonal 3 : "<<sum[2]<<endl;
	
	i=n;
	j=n;
	b=1;
	do
	{
		i--;
		j--;
		sum[3]+=a[i][j];
		b++;
	}while(b<=n/2);
	
	cout<<endl<<"Sum of half diagonal 4 : "<<sum[3]<<endl<<endl;
	
	if(sum[0]==sum[1] && sum[1]==sum[2] && sum[2]==sum[3])
	cout<<"Yes";
	
	else
	cout<<"No";
	
	return 0;
}





















